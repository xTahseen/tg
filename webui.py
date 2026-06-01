"""
SecureBox Web UI
Design: identical to Google Drive bot webui (dark theme, sidebar, breadcrumb,
FAB with New Folder + Upload File, selection bar, preview overlay, search modal).
Auth: password set via Telegram /setpassword, stored hashed in MongoDB per user.
Downloads: streamed via Pyrogram userbot (handles large files > 20 MB).
"""

import asyncio
import hashlib
import hmac
import json
import logging
import os
import time
from datetime import datetime
from functools import wraps

from aiohttp import web
from bson import ObjectId

logger = logging.getLogger(__name__)

# ─── Auth ─────────────────────────────────────────────────────────────────────

def _secret():
    return os.getenv("WEBUI_SECRET_KEY", "securebox-secret-change-me")

def _sign(payload: dict) -> str:
    import base64
    d = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    s = hmac.new(_secret().encode(), d.encode(), hashlib.sha256).hexdigest()
    return f"{d}.{s}"

def _verify(token: str):
    try:
        import base64
        d, s = token.rsplit(".", 1)
        if not hmac.compare_digest(s, hmac.new(_secret().encode(), d.encode(), hashlib.sha256).hexdigest()):
            return None
        p = json.loads(base64.urlsafe_b64decode(d).decode())
        return None if p.get("exp", 0) < time.time() else p
    except Exception:
        return None

def _make_token(uid: int) -> str:
    return _sign({"uid": uid, "exp": time.time() + 86400 * 7})

def _hash_pw(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def require_auth(handler):
    @wraps(handler)
    async def wrapper(request: web.Request):
        tok = request.cookies.get("session")
        p   = _verify(tok) if tok else None
        if not p:
            raise web.HTTPFound("/") if not request.path.startswith("/api/") \
                  else web.HTTPUnauthorized(reason="Not authenticated")
        request["uid"] = p["uid"]
        return await handler(request)
    return wrapper

def _fmt_size(b):
    if not b: return "0 B"
    b = int(b)
    for u in ("B","KB","MB","GB","TB"):
        if b < 1024: return f"{b} {u}" if u=="B" else f"{b:.1f} {u}"
        b /= 1024
    return f"{b:.2f} TB"

# ─── Icons ────────────────────────────────────────────────────────────────────

def _icon(name, size=20, cls="", bg=None):
    ca = f' class="{cls}"' if cls else ""
    M = {
        "folder":     '<path d="M2.25 12.75V12A2.25 2.25 0 014.5 9.75h15A2.25 2.25 0 0121.75 12v.75m-8.69-6.44l-2.12-2.12a1.5 1.5 0 00-1.061-.44H4.5A2.25 2.25 0 002.25 6v12a2.25 2.25 0 002.25 2.25h15A2.25 2.25 0 0021.75 18V9a2.25 2.25 0 00-2.25-2.25h-5.379a1.5 1.5 0 01-1.06-.44z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
        "file":       '<path d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m2.25 0H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
        "image":      '<path d="M2.25 15.75l5.159-5.159a2.25 2.25 0 013.182 0l5.159 5.159m-1.5-1.5l1.409-1.409a2.25 2.25 0 013.182 0l2.909 2.909m-18 3.75h16.5a1.5 1.5 0 001.5-1.5V6a1.5 1.5 0 00-1.5-1.5H3.75A1.5 1.5 0 002.25 6v12a1.5 1.5 0 001.5 1.5zm10.5-11.25h.008v.008h-.008V8.25zm.375 0a.375.375 0 11-.75 0 .375.375 0 01.75 0z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
        "video":      '<path d="M15.75 10.5l4.72-4.72a.75.75 0 011.28.53v11.38a.75.75 0 01-1.28.53l-4.72-4.72M4.5 18.75h9a2.25 2.25 0 002.25-2.25v-9a2.25 2.25 0 00-2.25-2.25h-9A2.25 2.25 0 002.25 7.5v9a2.25 2.25 0 002.25 2.25z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
        "audio":      '<path d="M9 9l10.5-3m0 6.553v3.75a2.25 2.25 0 01-1.632 2.163l-1.32.377a1.803 1.803 0 11-.99-3.467l2.31-.66a2.25 2.25 0 001.632-2.163zm0 0V2.25L9 5.25v10.303m0 0v3.75a2.25 2.25 0 01-1.632 2.163l-1.32.377a1.803 1.803 0 01-.99-3.467l2.31-.66A2.25 2.25 0 009 15.553z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
        "home":       '<path d="M2.25 12l8.954-8.955a1.126 1.126 0 011.591 0L21.75 12M4.5 9.75v10.125c0 .621.504 1.125 1.125 1.125H9.75v-4.875c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125V21h4.125c.621 0 1.125-.504 1.125-1.125V9.75M8.25 21h8.25" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "search":     '<path d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 15.803 7.5 7.5 0 0015.803 15.803z" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "back":       '<path d="M10.5 19.5L3 12m0 0l7.5-7.5M3 12h18" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "plus":       '<path d="M12 4.5v15m7.5-7.5h-15" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "close":      '<path d="M6 18L18 6M6 6l12 12" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "refresh":    '<path d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0l3.181 3.183a8.25 8.25 0 0013.803-3.7M4.031 9.865a8.25 8.25 0 0113.803-3.7l3.181 3.182m0-4.991v4.99" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "upload":     '<path d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "download":   '<path d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "delete":     '<path d="M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 01-2.244 2.077H8.084a2.25 2.25 0 01-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 00-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 013.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 00-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 00-7.5 0" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "rename":     '<path d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L6.832 19.82a4.5 4.5 0 01-1.897 1.13l-2.685.8.8-2.685a4.5 4.5 0 011.13-1.897L16.863 4.487zm0 0L19.5 7.125" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "move":       '<path d="M7.5 21L3 16.5m0 0L7.5 12M3 16.5h13.5m0-13.5L21 7.5m0 0L16.5 12M21 7.5H7.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "signout":    '<path d="M15.75 9V5.25A2.25 2.25 0 0013.5 3h-6a2.25 2.25 0 00-2.25 2.25v13.5A2.25 2.25 0 007.5 21h6a2.25 2.25 0 002.25-2.25V15M12 9l-3 3m0 0l3 3m-3-3h12.75" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "alert":      '<path d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "login":      '<path d="M15.75 9V5.25A2.25 2.25 0 0013.5 3h-6a2.25 2.25 0 00-2.25 2.25v13.5A2.25 2.25 0 007.5 21h6a2.25 2.25 0 002.25-2.25V15m3 0l3-3m0 0l-3-3m3 3H9" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "newfolder":  '<path d="M12 10.5v6m3-3H9m4.06-7.19l-2.12-2.12a1.5 1.5 0 00-1.061-.44H4.5A2.25 2.25 0 002.25 6v12a2.25 2.25 0 002.25 2.25h15A2.25 2.25 0 0021.75 18V9a2.25 2.25 0 00-2.25-2.25h-5.379a1.5 1.5 0 01-1.06-.44z" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "chevron_r":  '<path d="M8.25 4.5l7.5 7.5-7.5 7.5" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>',
        "lock":       '<path d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
    }
    path = M.get(name, M["file"])
    svg  = f'<svg{ca} width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">{path}</svg>'
    return f'<div class="icon-bg" style="background:{bg}">{svg}</div>' if bg else svg

def _file_icon(ft, size=20):
    m = {"photo":"#a78bfa","video":"#f87171","video_note":"#f87171",
         "audio":"#e55835","voice":"#fb923c","document":"#607d8b","sticker":"#818cf8"}
    icons = {"photo":"image","video":"video","video_note":"video",
             "audio":"audio","voice":"audio","sticker":"image"}
    return _icon(icons.get(ft,"file"), size, "", m.get(ft,"#607d8b"))

# ─── CSS (identical to GDrive bot webui) ──────────────────────────────────────

_CSS = """
:root{--bg:#000;--header:#171717;--surface:#1a1a1a;--surface2:#222;--surface3:#2a2a2a;
  --border:#2c2c2c;--border2:#3a3a3a;--accent:#0483c3;--accent2:#0369a1;
  --accent-dim:rgba(4,131,195,.13);--green:#22c55e;--red:#ef4444;--yellow:#f59e0b;
  --fab:#ffb200;--fab2:#e6a000;--text:#f0f0f0;--text2:#a0a0a0;--text3:#555;
  --folder:#0483c3;--r4:4px;--r8:8px;--r12:12px;--r16:16px;
  --sans:'Google Sans','Roboto','Segoe UI',system-ui,-apple-system,sans-serif;
  --shadow:0 8px 32px rgba(0,0,0,.6)}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{height:100%;-webkit-text-size-adjust:100%}
body{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:15px;
  height:100%;-webkit-font-smoothing:antialiased;overflow-x:hidden}
a{color:var(--accent);text-decoration:none}
::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:2px}

#bar{position:fixed;top:0;left:0;right:0;height:3px;background:var(--accent);
  transform:scaleX(0);transform-origin:left;transition:transform .4s;z-index:9999;opacity:0}
#bar.on{transform:scaleX(.7);opacity:1}
#bar.done{transform:scaleX(1);opacity:0;transition:transform .3s,opacity .4s .2s}

#toast{position:fixed;bottom:90px;left:50%;transform:translateX(-50%) translateY(20px);
  background:var(--surface2);border:1px solid var(--border2);color:var(--text);
  border-radius:24px;padding:12px 22px;font-size:14px;z-index:9999;opacity:0;
  pointer-events:none;transition:all .22s ease;white-space:nowrap;box-shadow:var(--shadow)}
#toast.show{transform:translateX(-50%) translateY(0);opacity:1}
#toast.ok{border-color:var(--green);color:var(--green)}
#toast.err{border-color:var(--red);color:var(--red)}
#toast.warn{border-color:var(--yellow);color:var(--yellow)}

.btn{display:inline-flex;align-items:center;gap:8px;border:none;border-radius:var(--r8);
  cursor:pointer;font-size:14px;font-weight:500;font-family:var(--sans);transition:all .15s;
  white-space:nowrap;padding:0 16px;height:40px}
.btn:active{transform:scale(.97)}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{background:var(--accent2)}
.btn-ghost{background:transparent;color:var(--text2);border:1px solid var(--border2)}
.btn-ghost:hover{background:var(--surface3);color:var(--text)}
.btn-danger{background:rgba(239,68,68,.15);color:var(--red);border:1px solid rgba(239,68,68,.3)}
.btn-danger:hover{background:rgba(239,68,68,.25)}
.btn-icon{width:40px;height:40px;padding:0;border-radius:var(--r8);background:transparent;
  color:var(--text2);border:none;justify-content:center;display:inline-flex;align-items:center}
.btn-icon:hover{background:var(--surface3);color:var(--text)}
.btn-sm{height:34px;padding:0 13px;font-size:13px}
.btn-wide{width:100%;justify-content:center}

input,select{background:var(--surface3);color:var(--text);border:1px solid var(--border);
  border-radius:var(--r8);padding:11px 14px;font-size:15px;font-family:var(--sans);
  width:100%;outline:none;transition:border-color .15s,box-shadow .15s}
input:focus,select:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-dim)}
input::placeholder{color:var(--text3)}

nav{background:#171717;padding:0 14px;display:flex;align-items:center;gap:10px;
  height:58px;position:sticky;top:0;z-index:200}
.nav-logo{display:flex;align-items:center;gap:10px;text-decoration:none;flex-shrink:0}
.nav-logo-icon{color:var(--accent)}
.nav-center{flex:1;display:flex;justify-content:center;padding:0 8px}
.nav-search-wrap{display:flex;align-items:center;gap:8px;background:rgba(255,255,255,.07);
  border:1px solid rgba(255,255,255,.1);border-radius:24px;padding:0 14px;height:38px;
  width:100%;max-width:420px;transition:background .18s,border-color .18s,box-shadow .18s}
.nav-search-wrap:focus-within{background:rgba(255,255,255,.11);border-color:var(--accent);
  box-shadow:0 0 0 3px var(--accent-dim)}
.nav-search-wrap svg{color:var(--text3);flex-shrink:0}
#nav-search-input{background:transparent;border:none;outline:none;color:var(--text);
  font-size:14px;font-family:var(--sans);width:100%;padding:0;box-shadow:none}
#nav-search-input::placeholder{color:var(--text3)}

.toolbar{display:flex;align-items:center;gap:8px;padding:10px 14px;background:#171717;
  flex-shrink:0;min-height:52px}
.breadcrumb{display:flex;align-items:center;gap:2px;flex:1;min-width:0;overflow-x:auto;
  overflow-y:hidden;scrollbar-width:none;-ms-overflow-style:none}
.breadcrumb::-webkit-scrollbar{display:none}
.bc-crumb{color:var(--text2);cursor:pointer;padding:5px 8px;border-radius:var(--r4);
  font-size:15px;text-transform:uppercase;white-space:nowrap;transition:all .1s;flex-shrink:0}
.bc-crumb:hover{background:var(--surface2);color:var(--text)}
.bc-crumb.last{color:var(--accent);cursor:default;font-weight:600}
.bc-crumb.last:hover{background:transparent}
.bc-sep{color:var(--text3);flex-shrink:0;font-size:25px}

.layout{display:flex;height:calc(100vh - 58px);overflow:hidden}

.sidebar{width:230px;flex-shrink:0;background:var(--header);border-right:1px solid var(--border);
  padding:12px 8px;display:flex;flex-direction:column;gap:2px;overflow-y:auto}
.sb-item{display:flex;align-items:center;gap:10px;padding:11px 12px;border-radius:var(--r8);
  cursor:pointer;font-size:15px;font-weight:500;color:var(--text2);transition:all .12s;
  border:1px solid transparent}
.sb-item:hover{background:var(--surface2);color:var(--text)}
.sb-item.active{background:var(--accent-dim);color:var(--accent);border-color:rgba(4,131,195,.2)}
.sb-item svg{flex-shrink:0}
.sb-divider{height:1px;background:var(--border);margin:8px 4px}
.sb-label{font-size:11px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;
  color:var(--text3);padding:8px 12px 3px}
.sb-folder{display:flex;align-items:center;gap:8px;padding:9px 12px;border-radius:var(--r8);
  cursor:pointer;font-size:13px;color:var(--text2);transition:all .12s;border:1px solid transparent}
.sb-folder:hover{background:var(--surface2);color:var(--text)}
.sb-folder.active{background:var(--accent-dim);color:var(--accent)}
.sb-folder-name{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex:1}

.main{flex:1;display:flex;flex-direction:column;overflow:hidden;min-width:0}
.file-area{flex:1;overflow-y:auto;padding-bottom:100px}

.file-item{display:flex;align-items:center;gap:16px;padding:10px 12px;
  border-bottom:.9px solid rgba(44,44,44,.6);cursor:pointer;transition:background .08s;
  position:relative;user-select:none;-webkit-user-select:none}
.file-item:active{background:var(--surface2)}
.file-item.sel{background:rgba(4,131,195,.1)}
.file-item.sel .fi-cb{display:flex}
.fi-cb{display:none;width:20px;height:20px;flex-shrink:0;align-items:center;justify-content:center}
body.select-mode .fi-cb{display:flex}

.custom-cb{width:20px;height:20px;border-radius:50%;border:2px solid var(--border2);
  background:transparent;display:flex;align-items:center;justify-content:center;
  cursor:pointer;transition:all .18s ease;flex-shrink:0;position:relative}
.custom-cb.checked{background:var(--accent);border-color:var(--accent);
  box-shadow:0 2px 8px rgba(4,131,195,.4)}
.custom-cb.checked::after{content:'';width:7px;height:4px;background:transparent;
  border-radius:0;border-left:2px solid #fff;border-bottom:2px solid #fff;
  transform:rotate(-45deg) translateY(-1px);position:static}
.custom-cb:not(.checked):hover{border-color:var(--accent);background:var(--accent-dim)}

.fi-icon{flex-shrink:0;display:flex;align-items:center;justify-content:center;width:46px;height:46px}
.icon-bg{display:flex;align-items:center;justify-content:center;width:46px;height:46px;
  border-radius:50%;flex-shrink:0;box-shadow:0 2px 8px rgba(0,0,0,.3)}
.icon-bg svg{width:24px;height:24px;color:white;stroke:white}
.fi-info{flex:1;min-width:0;overflow:hidden}
.fi-name{font-size:16px;font-weight:400;color:var(--text);white-space:nowrap;
  overflow:hidden;text-overflow:ellipsis;line-height:1.3}
.fi-name.fol{font-weight:400}
.fi-meta{display:flex;justify-content:space-between;align-items:center;margin-top:3px;width:100%}
.fi-size{font-size:12px;color:var(--text3)}
.fi-date{font-size:12px;color:var(--text3);margin-left:auto;padding-left:8px;white-space:nowrap}
.fi-act{position:absolute;right:10px;top:50%;transform:translateY(-50%);
  opacity:0;transition:opacity .15s;pointer-events:none}
@media(hover:hover){.file-item:hover .fi-act{opacity:1;pointer-events:auto}}

.empty{display:flex;flex-direction:column;align-items:center;justify-content:center;
  padding:80px 24px;gap:16px;color:var(--text3)}
.empty-icon{color:var(--text3);opacity:.35}
.empty h3{font-size:20px;font-weight:600;color:var(--text2)}
.empty p{font-size:14px}

.sk{background:linear-gradient(90deg,var(--surface) 25%,var(--surface3) 50%,var(--surface) 75%);
  background-size:200% 100%;animation:sk 1.4s infinite;border-radius:var(--r4)}
@keyframes sk{0%{background-position:200% 0}100%{background-position:-200% 0}}
.sk-n{height:15px;width:55%}.sk-s{height:12px;width:30%}
.sk-i{height:46px;width:46px;border-radius:50%;flex-shrink:0}

#fab{position:fixed;bottom:24px;right:20px;z-index:400;display:flex;
  flex-direction:column;align-items:flex-end;gap:12px;transition:bottom .3s ease}
body.select-mode #fab{bottom:96px}
.fab-main{width:58px;height:58px;border-radius:50%;background:var(--fab);color:#fff;
  border:none;display:flex;align-items:center;justify-content:center;cursor:pointer;
  box-shadow:0 4px 20px rgba(255,178,0,.4);transition:all .2s;flex-shrink:0}
.fab-main:hover{background:var(--fab2);transform:scale(1.06)}
.fab-main:active{transform:scale(.96)}
.fab-main.open{transform:rotate(45deg)}
.fab-main.open:hover{transform:rotate(45deg) scale(1.06)}
.fab-options{display:flex;flex-direction:column;align-items:flex-end;gap:10px;
  transform-origin:bottom right;animation:fabIn .18s ease}
@keyframes fabIn{from{opacity:0;transform:scale(.85) translateY(10px)}}
.fab-opt{display:flex;align-items:center;gap:10px;background:var(--surface2);
  border:1px solid var(--border2);border-radius:28px;padding:10px 18px 10px 14px;
  cursor:pointer;font-size:14px;font-weight:600;color:var(--text);
  box-shadow:0 4px 16px rgba(0,0,0,.5);transition:all .15s;white-space:nowrap}
.fab-opt:hover{background:var(--surface3);border-color:var(--accent);color:var(--accent)}
.fab-opt svg{flex-shrink:0}

#selbar{position:fixed;bottom:20px;left:50%;transform:translateX(-50%) translateY(100px);
  background:var(--surface2);border:1px solid var(--border2);border-radius:36px;
  padding:10px 14px;display:flex;align-items:center;gap:6px;
  box-shadow:0 8px 40px rgba(0,0,0,.7);z-index:500;opacity:0;pointer-events:none;
  transition:transform .28s cubic-bezier(.34,1.56,.64,1),opacity .18s;
  max-width:calc(100vw - 32px)}
#selbar.show{transform:translateX(-50%) translateY(0);opacity:1;pointer-events:auto}
#selcnt{font-size:13px;color:var(--text2);padding:0 4px;white-space:nowrap}
.selbar-sep{width:1px;height:22px;background:var(--border2);margin:0 2px;flex-shrink:0}
.sel-btn{display:flex;flex-direction:column;align-items:center;gap:2px;background:transparent;
  border:none;cursor:pointer;padding:6px 8px;border-radius:var(--r8);color:var(--text2);
  transition:all .12s;flex-shrink:0}
.sel-btn:hover{background:var(--surface3);color:var(--text)}
.sel-btn.danger{color:var(--red)}
.sel-btn.danger:hover{background:rgba(239,68,68,.15)}
.sel-btn span{font-size:10px;font-weight:600;white-space:nowrap}
.sel-close{width:30px;height:30px;border-radius:50%;background:var(--surface3);border:none;
  cursor:pointer;display:flex;align-items:center;justify-content:center;
  color:var(--text3);flex-shrink:0;margin-left:2px}
.sel-close:hover{color:var(--text);background:var(--border2)}

.moverlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);
  backdrop-filter:blur(6px);z-index:1000;align-items:center;justify-content:center;padding:16px}
.moverlay.open{display:flex}
.modal{background:var(--surface);border:1px solid var(--border2);border-radius:var(--r16);
  padding:22px 20px;width:100%;max-width:420px;box-shadow:var(--shadow);
  animation:mIn .2s ease;max-height:88vh;overflow-y:auto}
@keyframes mIn{from{transform:scale(.95) translateY(-8px);opacity:0}}
.modal-title{font-size:16px;font-weight:700;margin-bottom:16px;display:flex;
  align-items:center;gap:9px;color:var(--text)}
.fg{margin-bottom:14px}
.fg label{display:block;font-size:11px;color:var(--text3);margin-bottom:5px;
  text-transform:uppercase;letter-spacing:.05em;font-weight:600}
.macts{display:flex;gap:8px;justify-content:flex-end;margin-top:18px}

#preview-overlay{display:none;position:fixed;inset:0;z-index:2000;background:#000;flex-direction:column}
#preview-overlay.open{display:flex}
#preview-bar{display:flex;align-items:center;gap:10px;padding:10px 14px;
  background:rgba(0,0,0,.85);backdrop-filter:blur(12px);
  border-bottom:1px solid rgba(255,255,255,.07);flex-shrink:0;min-height:52px}
#preview-title{flex:1;min-width:0;font-size:14px;font-weight:500;color:var(--text);
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
#preview-dl-btn{width:36px;height:36px;border-radius:50%;border:none;cursor:pointer;
  background:rgba(255,255,255,.1);color:var(--text);display:flex;align-items:center;
  justify-content:center;flex-shrink:0;transition:background .15s}
#preview-dl-btn:hover{background:var(--accent);color:#fff}
#preview-close-btn{width:36px;height:36px;border-radius:50%;border:none;cursor:pointer;
  background:rgba(255,255,255,.08);color:var(--text2);display:flex;align-items:center;
  justify-content:center;flex-shrink:0;transition:background .15s,color .15s}
#preview-close-btn:hover{background:rgba(239,68,68,.25);color:#ef4444}
#preview-body{flex:1;overflow:auto;display:flex;align-items:center;justify-content:center;
  padding:0;position:relative;background:#000}
#preview-body iframe{width:100%;height:100%;border:none;background:#fff}
#preview-body img{max-width:100%;max-height:100%;object-fit:contain}
#preview-body video,#preview-body audio{max-width:100%;max-height:100%}
#preview-spinner{position:absolute;inset:0;display:flex;align-items:center;
  justify-content:center;background:#000;z-index:5}
#preview-spinner svg{animation:spin 1s linear infinite;color:var(--accent)}
@keyframes spin{to{transform:rotate(360deg)}}
#preview-unsupported{display:flex;flex-direction:column;align-items:center;
  justify-content:center;text-align:center;padding:48px 32px;gap:0;min-height:320px}
.pu-icon-wrap{width:96px;height:96px;border-radius:50%;background:rgba(255,255,255,.05);
  border:1px solid rgba(255,255,255,.1);display:flex;align-items:center;justify-content:center;
  margin-bottom:24px;opacity:.75}
#preview-unsupported h3{font-size:20px;font-weight:700;color:var(--text);margin-bottom:10px}
#preview-unsupported p{font-size:14px;color:var(--text3);margin-bottom:28px;max-width:340px;line-height:1.6}
.pu-dl-btn{display:inline-flex;align-items:center;gap:10px;padding:13px 28px;
  border-radius:50px;border:none;cursor:pointer;background:var(--accent);color:#fff;
  font-size:15px;font-weight:600;font-family:var(--sans);transition:all .2s;
  box-shadow:0 4px 20px rgba(4,131,195,.4)}
.pu-dl-btn:hover{filter:brightness(1.12);transform:translateY(-1px)}

.dropzone{border:2px dashed var(--border2);border-radius:var(--r12);padding:24px 16px;
  text-align:center;color:var(--text3);cursor:pointer;transition:all .18s;position:relative}
.dropzone:hover,.dropzone.dragover{border-color:var(--accent);color:var(--accent);background:var(--accent-dim)}
.dropzone input[type=file]{position:absolute;inset:0;opacity:0;cursor:pointer;font-size:0}
.dz-icon{margin:0 auto 8px}
.dz-txt{font-size:15px;font-weight:600;margin-top:2px}
.dz-hint{font-size:12px;margin-top:4px;opacity:.7}
.ulist{margin-top:10px;max-height:160px;overflow-y:auto;display:flex;flex-direction:column;gap:6px}
.uitem{padding:9px 11px;background:var(--surface2);border-radius:var(--r8);font-size:13px}
.uitem-top{display:flex;align-items:center;gap:10px}
.uname{flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ust{color:var(--text3);white-space:nowrap}
.ubar{height:3px;background:var(--border);border-radius:99px;overflow:hidden;margin-top:7px}
.ufill{height:100%;background:var(--accent);border-radius:99px;transition:width .25s;width:0}

.ftree{max-height:220px;overflow-y:auto;border:1px solid var(--border);border-radius:var(--r8)}
.fti{display:flex;align-items:center;gap:10px;padding:12px 14px;cursor:pointer;font-size:14px;
  border-bottom:1px solid rgba(44,44,44,.4);transition:background .09s}
.fti:last-child{border-bottom:none}
.fti:hover{background:var(--surface2)}
.fti.sel{background:var(--accent-dim);color:var(--accent)}

.sri{display:flex;align-items:center;gap:14px;padding:10px 12px;cursor:pointer;
  border-bottom:.9px solid rgba(44,44,44,.6);transition:background .08s}
.sri:last-child{border-bottom:none}
.sri:active{background:var(--surface2)}
.sri-icon{flex-shrink:0;display:flex;align-items:center;justify-content:center;width:46px;height:46px}
.sri-info{flex:1;min-width:0;overflow:hidden}
.sri-name{font-size:15px;font-weight:400;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sri-meta{display:flex;justify-content:space-between;align-items:center;margin-top:3px}
.sri-size{font-size:12px;color:var(--text3)}
.sri-date{font-size:12px;color:var(--text3);margin-left:auto;padding-left:8px;white-space:nowrap}

.lp{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.lcard{background:var(--header);border:1px solid var(--border2);border-radius:var(--r16);
  padding:40px 32px;width:100%;max-width:380px;box-shadow:var(--shadow)}
.llogo{text-align:center;margin-bottom:32px}
.llogo-icon{color:var(--accent);margin:0 auto 16px}
.llogo h1{font-size:26px;font-weight:800}
.llogo p{color:var(--text2);font-size:14px;margin-top:6px}
.lerr{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);border-radius:var(--r8);
  padding:12px 14px;color:var(--red);font-size:14px;margin-bottom:16px;display:flex;align-items:center;gap:8px}
.lhint{font-size:12px;color:var(--text3);text-align:center;margin-top:20px;line-height:1.6}

@media(max-width:640px){
  .sidebar{display:none}
  nav{padding:0 10px;gap:6px}
  .nav-search-wrap{max-width:100%}
  .toolbar{padding:8px 12px}
  .fab-main{width:54px;height:54px}
  #selbar{padding:8px 10px;gap:2px}
  .sel-btn span{display:none}
  .moverlay{padding:12px}
}
"""

_JS = """
function toast(msg,type=''){
  const t=document.getElementById('toast');
  t.textContent=msg;t.className='show '+type;
  clearTimeout(t._t);t._t=setTimeout(()=>t.className='',3500);
}
function bar(on){
  const b=document.getElementById('bar');b.className=on?'on':'done';
  if(!on)setTimeout(()=>b.className='',800);
}
function openModal(id){document.getElementById('m-'+id).classList.add('open');}
function closeModal(id){document.getElementById('m-'+id).classList.remove('open');}
document.addEventListener('DOMContentLoaded',()=>{
  document.querySelectorAll('.moverlay').forEach(el=>
    el.addEventListener('click',e=>{if(e.target===el)el.classList.remove('open');}));
  if(typeof initPage==='function')initPage();
});
"""

def _page(body, title="SecureBox"):
    return web.Response(content_type="text/html", text=f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<title>{title} — SecureBox</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Google+Sans:wght@400;500;700&family=Roboto:wght@400;500;700&display=swap" rel="stylesheet">
<style>{_CSS}</style>
</head><body>
<div id="bar"></div><div id="toast"></div>
{body}
<script>{_JS}</script>
</body></html>""")

# ─── Login ─────────────────────────────────────────────────────────────────────

async def handle_login(request: web.Request) -> web.Response:
    tok = request.cookies.get("session")
    if tok and _verify(tok):
        raise web.HTTPFound("/files")

    error = ""
    if request.method == "POST":
        data = await request.post()
        pw   = data.get("password", "")
        settings_col = request.app["settings_col"]
        # Find any user's hashed password (single-user scenario)
        doc = await settings_col.find_one({})
        if doc:
            ok = _hash_pw(pw) == doc.get("webui_password_hash", "")
        else:
            ok = True  # no password set yet — allow open access

        if ok:
            uid = doc["user_id"] if doc else 0
            resp = web.HTTPFound("/files")
            resp.set_cookie("session", _make_token(uid), max_age=86400*7, httponly=True, samesite="Lax")
            raise resp
        else:
            error = "Incorrect password."

    err_html = f'<div class="lerr">{_icon("alert",16)} {error}</div>' if error else ""
    return _page(f"""
<div class="lp"><div class="lcard">
  <div class="llogo">
    <div class="llogo-icon">{_icon("lock",52)}</div>
    <h1>SecureBox</h1>
    <p>Sign in to manage your files</p>
  </div>
  {err_html}
  <form method="POST">
    <div class="fg"><label>Password</label>
      <input name="password" type="password" placeholder="Enter your password"
        autofocus autocomplete="current-password"></div>
    <button type="submit" class="btn btn-primary btn-wide" style="height:46px;margin-top:8px;font-size:16px">
      {_icon("login",18)} Sign In
    </button>
  </form>
  <p class="lhint">Set password via Telegram:<br><code>/setpassword yourpassword</code></p>
</div></div>""", "Sign In")

async def handle_logout(request: web.Request) -> web.Response:
    r = web.HTTPFound("/")
    r.del_cookie("session")
    raise r

# ─── Main file browser ─────────────────────────────────────────────────────────

@require_auth
async def handle_files(request: web.Request) -> web.Response:
    uid          = request["uid"]
    folders_col  = request.app["folders_col"]

    # Build sidebar folder list (root folders)
    cursor = folders_col.find({"user_id": uid, "parent": None}).sort("name", 1)
    root_folders = await cursor.to_list(length=100)

    sidebar_folders_html = ""
    for f in root_folders:
        fn = f["name"].replace("'","&#39;").replace('"',"&quot;")
        sidebar_folders_html += f"""<div class="sb-folder" data-folder="{fn}"
          onclick="navFolder('{fn}',null)">{_icon("folder",14)} <span class="sb-folder-name">{f['name']}</span></div>"""

    skel = "".join(f"""<div class="file-item">
      <div class="fi-cb"><div class="custom-cb"></div></div>
      <div class="sk sk-i"></div>
      <div class="fi-info">
        <div class="sk sk-n" style="margin-bottom:6px"></div>
        <div class="sk sk-s"></div>
      </div></div>""" for _ in range(10))

    IC = {
        "folder": _icon("folder",32,"","#0483c3").replace("'","&#39;"),
        "file":   _icon("file",32,"","#607d8b").replace("'","&#39;"),
        "image":  _icon("image",32,"","#a78bfa").replace("'","&#39;"),
        "video":  _icon("video",32,"","#f87171").replace("'","&#39;"),
        "audio":  _icon("audio",32,"","#e55835").replace("'","&#39;"),
        "dl":     _icon("download",20).replace("'","&#39;"),
        "rename": _icon("rename",20).replace("'","&#39;"),
        "del":    _icon("delete",20).replace("'","&#39;"),
        "move":   _icon("move",20).replace("'","&#39;"),
    }

    return _page(f"""
<nav>
  <a href="/files" class="nav-logo" title="SecureBox">
    {_icon("lock",28,"nav-logo-icon")}
    <span style="font-size:18px;font-weight:800;color:var(--text)">Secure<span style="color:var(--accent)">Box</span></span>
  </a>
  <div class="nav-center">
    <div class="nav-search-wrap">
      {_icon("search",16)}
      <input id="nav-search-input" type="text" placeholder="Search files and folders…"
        onkeydown="if(event.key==='Enter')doNavSearch()"
        oninput="onNavSearchInput(this.value)">
    </div>
  </div>
  <a href="/logout" class="btn btn-ghost btn-sm">{_icon("signout",16)} Sign out</a>
</nav>

<div class="layout">
  <aside class="sidebar">
    <div class="sb-item active" id="sb-home" onclick="navRoot()">{_icon("home",18)} My Files</div>
    <div class="sb-item" onclick="openSearchModal()">{_icon("search",18)} Search</div>
    <div class="sb-divider"></div>
    <div class="sb-label">Folders</div>
    {sidebar_folders_html}
    <div class="sb-divider"></div>
    <a href="/logout" class="sb-item" style="color:var(--red)">{_icon("signout",18)} Sign out</a>
  </aside>

  <div class="main">
    <div class="toolbar">
      <button class="btn btn-icon" id="back-btn" onclick="goBack()" style="display:none">{_icon("back",20)}</button>
      <div class="breadcrumb" id="bc"><span class="bc-crumb last">My Files</span></div>
    </div>
    <div class="file-area" id="file-area">
      <div id="fl">{skel}</div>
    </div>
  </div>
</div>

<!-- FAB — identical to Google Drive webui -->
<div id="fab">
  <div id="fab-opts" class="fab-options" style="display:none"></div>
  <button class="fab-main" id="fab-btn" onclick="toggleFab()" title="New">
    {_icon("plus",26)}
  </button>
</div>

<!-- Selection bar -->
<div id="selbar">
  <button class="sel-close" onclick="clearSel()">{_icon("close",14)}</button>
  <span id="selcnt">0 selected</span>
  <div class="selbar-sep"></div>
  <button class="sel-btn" onclick="selDl()" title="Download">{_icon("download",20)}<span>Download</span></button>
  <button class="sel-btn" onclick="selRename()" title="Rename">{_icon("rename",20)}<span>Rename</span></button>
  <button class="sel-btn" onclick="selMove()" title="Move">{_icon("move",20)}<span>Move</span></button>
  <button class="sel-btn danger" onclick="selDel()" title="Delete">{_icon("delete",20)}<span>Delete</span></button>
</div>

<!-- Rename modal -->
<div class="moverlay" id="m-rename"><div class="modal">
  <div class="modal-title">{_icon("rename",18)} Rename</div>
  <div class="fg"><label>New name</label><input id="i-rename" type="text"></div>
  <div class="macts">
    <button class="btn btn-ghost btn-sm" onclick="closeModal('rename')">Cancel</button>
    <button class="btn btn-primary btn-sm" onclick="doRename()">Rename</button>
  </div>
</div></div>

<!-- New folder modal -->
<div class="moverlay" id="m-mkdir"><div class="modal">
  <div class="modal-title">{_icon("newfolder",18)} New Folder</div>
  <div class="fg"><label>Folder name</label><input id="i-mkdir" type="text" placeholder="Untitled folder"></div>
  <div class="fg">
    <label>Parent folder (optional)</label>
    <select id="i-mkdir-parent"><option value="">— Root —</option></select>
  </div>
  <div class="macts">
    <button class="btn btn-ghost btn-sm" onclick="closeModal('mkdir')">Cancel</button>
    <button class="btn btn-primary btn-sm" onclick="doMkdir()">Create</button>
  </div>
</div></div>

<!-- Delete modal -->
<div class="moverlay" id="m-delete"><div class="modal">
  <div class="modal-title">{_icon("delete",18)} Delete</div>
  <p id="del-msg" style="color:var(--text2);font-size:14px;margin-bottom:6px"></p>
  <p style="font-size:12px;color:var(--text3)">This action cannot be undone.</p>
  <div class="macts">
    <button class="btn btn-ghost btn-sm" onclick="closeModal('delete')">Cancel</button>
    <button class="btn btn-danger btn-sm" onclick="doDelete()">Delete</button>
  </div>
</div></div>

<!-- Upload modal -->
<div class="moverlay" id="m-upload"><div class="modal">
  <div class="modal-title">{_icon("upload",18)} Upload Files</div>
  <div class="dropzone" id="dz">
    <input type="file" id="fi" multiple onchange="addFiles(this.files)">
    <div class="dz-icon">{_icon("upload",34)}</div>
    <div class="dz-txt">Drop files here or tap to browse</div>
    <div class="dz-hint">Files are stored in Telegram storage channel</div>
  </div>
  <div class="ulist" id="ulist"></div>
  <div class="macts" style="margin-top:14px">
    <button class="btn btn-ghost btn-sm" onclick="closeModal('upload');uploadQ=[];document.getElementById('ulist').innerHTML='';document.getElementById('fi').value=''">Cancel</button>
    <button class="btn btn-primary btn-sm" id="ubtn" onclick="startUpload()">{_icon("upload",15)} Upload</button>
  </div>
</div></div>

<!-- Move modal -->
<div class="moverlay" id="m-move"><div class="modal">
  <div class="modal-title">{_icon("move",18)} Move to Folder</div>
  <p style="font-size:12px;color:var(--text3);margin-bottom:10px">Select destination folder</p>
  <div class="ftree" id="move-tree"></div>
  <div class="macts">
    <button class="btn btn-ghost btn-sm" onclick="closeModal('move')">Cancel</button>
    <button class="btn btn-primary btn-sm" onclick="confirmMove()">Move here</button>
  </div>
</div></div>

<!-- Search modal -->
<div class="moverlay" id="m-search"><div class="modal" style="max-width:480px">
  <div class="modal-title">{_icon("search",18)} Search Files</div>
  <div class="fg" style="display:flex;gap:8px;margin-bottom:0">
    <input id="i-search" type="text" placeholder="Search by name or folder..." style="flex:1">
    <button class="btn btn-primary" onclick="doSearch()" style="flex-shrink:0">{_icon("search",16)}</button>
  </div>
  <div id="search-res" style="max-height:340px;overflow-y:auto;margin-top:12px;border:1px solid var(--border);border-radius:var(--r8)"></div>
  <div class="macts"><button class="btn btn-ghost btn-sm" onclick="closeModal('search')">Close</button></div>
</div></div>

<!-- Preview overlay -->
<div id="preview-overlay">
  <div id="preview-bar">
    <button id="preview-close-btn" onclick="closePreview()">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
    </button>
    <span id="preview-title"></span>
    <button id="preview-dl-btn" onclick="previewDownload()" title="Download">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3"/></svg>
    </button>
  </div>
  <div id="preview-body">
    <div id="preview-spinner" style="display:none">
      <svg width="42" height="42" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg>
    </div>
  </div>
</div>

<!-- Icon data store -->
<div id="icons" style="display:none"
  data-folder="{IC['folder']}" data-file="{IC['file']}" data-image="{IC['image']}"
  data-video="{IC['video']}" data-audio="{IC['audio']}" data-dl="{IC['dl']}"
  data-rename="{IC['rename']}" data-del="{IC['del']}" data-move="{IC['move']}"></div>

<script>
const IC = document.getElementById('icons').dataset;
function getIco(ft){{
  if(ft==='photo') return IC.image;
  if(ft==='video'||ft==='video_note') return IC.video;
  if(ft==='audio'||ft==='voice') return IC.audio;
  if(ft==='folder') return IC.folder;
  return IC.file;
}}

let files=[], folders=[], sel=new Set();
let renameId=null, delIds=[], moveIds=[];
let currentFolder=null, stack=[], fabOpen=false;
let longPressTimer=null, _pvId=null;
let uploadQ=[];

function sz(b){{if(!b||isNaN(b))return'—';b=+b;if(b<1024)return b+' B';if(b<1048576)return(b/1024).toFixed(1)+' KB';if(b<1073741824)return(b/1048576).toFixed(1)+' MB';return(b/1073741824).toFixed(2)+' GB'}}
function dt(s){{if(!s)return'—';const d=new Date(s),now=new Date(),diff=now-d;if(diff<86400000)return d.toLocaleTimeString([],{{hour:'2-digit',minute:'2-digit'}});if(diff<604800000)return d.toLocaleDateString([],{{weekday:'short',month:'short',day:'numeric'}});return d.toLocaleDateString([],{{year:'numeric',month:'short',day:'numeric'}})}}

function initPage(){{ navRoot(); }}

function navRoot(){{
  currentFolder=null; stack=[];
  document.querySelectorAll('.sb-folder').forEach(e=>e.classList.remove('active'));
  document.getElementById('sb-home').classList.add('active');
  renderBC(); load();
}}

function navFolder(name, parent){{
  currentFolder=name;
  const i=stack.findIndex(x=>x.name===name);
  if(i>=0) stack=stack.slice(0,i+1);
  else stack.push({{name,parent}});
  document.querySelectorAll('.sb-folder').forEach(e=>e.classList.toggle('active',e.dataset.folder===name));
  document.getElementById('sb-home').classList.remove('active');
  renderBC(); load();
}}

function goBack(){{
  stack.pop();
  if(stack.length===0){{ navRoot(); return; }}
  const s=stack[stack.length-1];
  currentFolder=s.name; renderBC(); load();
}}

function renderBC(){{
  let h=`<span class="bc-crumb" onclick="navRoot()">My Files</span>`;
  stack.forEach((f,i)=>{{
    const last=i===stack.length-1;
    h+=`<span class="bc-sep">›</span><span class="bc-crumb${{last?' last':''}}" onclick="navFolder('${{f.name}}','${{f.parent||''}}')">
      ${{f.name}}</span>`;
  }});
  const bc=document.getElementById('bc');
  bc.innerHTML=h;
  setTimeout(()=>bc.scrollLeft=bc.scrollWidth,0);
  document.getElementById('back-btn').style.display=stack.length?'':'none';
}}

async function load(){{
  sel.clear(); clearSel(); closeFab();
  const fl=document.getElementById('fl');
  fl.innerHTML=Array(8).fill(`<div class="file-item">
    <div class="fi-cb"><div class="custom-cb"></div></div>
    <div class="sk sk-i"></div>
    <div class="fi-info"><div class="sk sk-n" style="margin-bottom:6px"></div><div class="sk sk-s"></div>
    </div></div>`).join('');
  bar(true);
  try{{
    let url='/api/files';
    if(currentFolder) url+='?folder='+encodeURIComponent(currentFolder);
    const r=await fetch(url); if(!r.ok) throw new Error('HTTP '+r.status);
    const d=await r.json();
    folders=d.folders||[]; files=d.files||[];
    render();
  }}catch(e){{
    fl.innerHTML=`<div class="empty"><div class="empty-icon">${{IC.file}}</div><h3>Failed to load</h3><p>${{e.message}}</p></div>`;
  }}
  bar(false);
}}

function _folderItemHTML(f){{
  const fn=f.name.replace(/"/g,'&quot;').replace(/'/g,'&#39;');
  return`<div class="file-item" data-id="folder_${{fn}}" data-name="${{fn}}" data-fol="true"
      onclick="navFolder('${{fn}}','${{currentFolder||''}}')"
      oncontextmenu="event.preventDefault()" >
    <div class="fi-cb"><div class="custom-cb"></div></div>
    <div class="fi-icon">${{IC.folder}}</div>
    <div class="fi-info">
      <div class="fi-name fol">${{f.name}}</div>
      <div class="fi-meta"><span class="fi-size">Folder</span></div>
    </div>
  </div>`;
}}

function _fileItemHTML(f){{
  const nm=f.file_name.replace(/"/g,'&quot;').replace(/'/g,'&#39;');
  const selCls=sel.has(f._id)?' sel':'';
  const chkCls=sel.has(f._id)?'custom-cb checked':'custom-cb';
  return`<div class="file-item${{selCls}}" data-id="${{f._id}}" data-name="${{nm}}" data-fol="false"
      onclick="itemClick(event,'${{f._id}}')"
      oncontextmenu="event.preventDefault();longPress('${{f._id}}')"
      ontouchstart="startLong(event,'${{f._id}}')" ontouchend="endLong()" ontouchmove="endLong()">
    <div class="fi-cb" onclick="event.stopPropagation();toggleSelCustom('${{f._id}}',this.querySelector('.custom-cb'))">
      <div class="${{chkCls}}"></div>
    </div>
    <div class="fi-icon">${{getIco(f.file_type)}}</div>
    <div class="fi-info">
      <div class="fi-name">${{f.file_name}}</div>
      <div class="fi-meta">
        <span class="fi-size">${{sz(f.file_size)}} · ${{f.file_type}}</span>
        <span class="fi-date">${{dt(f.message_date)}}</span>
      </div>
    </div>
    <button class="btn-icon fi-act" title="Download" onclick="event.stopPropagation();dlFile('${{f._id}}')">
      ${{IC.dl}}</button>
  </div>`;
}}

function render(){{
  const fl=document.getElementById('fl');
  if(!folders.length&&!files.length){{
    fl.innerHTML=`<div class="empty"><div class="empty-icon">${{IC.folder}}</div><h3>This folder is empty</h3><p>Upload files or create a subfolder</p></div>`;
    return;
  }}
  fl.innerHTML=folders.map(f=>_folderItemHTML(f)).join('')+files.map(f=>_fileItemHTML(f)).join('');
}}

function itemClick(e,id){{
  if(e.target.classList.contains('custom-cb'))return;
  if(document.body.classList.contains('select-mode')){{
    const cb=e.currentTarget.querySelector('.custom-cb');if(cb)toggleSelCustom(id,cb);return;
  }}
  const f=files.find(x=>x._id===id);
  if(f) openPreview(id,f.file_type,f.file_name);
}}

function startLong(e,id){{longPressTimer=setTimeout(()=>longPress(id),500);}}
function endLong(){{clearTimeout(longPressTimer);}}
function longPress(id){{
  if(!document.body.classList.contains('select-mode')) document.body.classList.add('select-mode');
  const row=document.querySelector(`[data-id="${{id}}"]`);
  const cb=row?.querySelector('.custom-cb');
  if(cb&&!cb.classList.contains('checked')) toggleSelCustom(id,cb);
}}

function toggleSelCustom(id,cb){{
  const chk=cb.classList.contains('checked');
  if(chk){{cb.classList.remove('checked');sel.delete(id);}}
  else{{cb.classList.add('checked');sel.add(id);}}
  document.querySelector(`.file-item[data-id="${{id}}"]`)?.classList.toggle('sel',!chk);
  if(!document.body.classList.contains('select-mode')) document.body.classList.add('select-mode');
  updateSel();
}}
function updateSel(){{
  document.getElementById('selcnt').textContent=sel.size+' selected';
  document.getElementById('selbar').classList.toggle('show',sel.size>0);
  if(!sel.size) document.body.classList.remove('select-mode');
}}
function clearSel(){{
  sel.clear();
  document.querySelectorAll('.file-item .custom-cb').forEach(c=>c.classList.remove('checked'));
  document.querySelectorAll('.file-item.sel').forEach(r=>r.classList.remove('sel'));
  document.body.classList.remove('select-mode');
  document.getElementById('selbar').classList.remove('show');
  updateSel();
}}

function dlFile(id){{ window.open(`/api/download/${{id}}`,'_blank'); }}
function selDl(){{[...sel].forEach(id=>window.open(`/api/download/${{id}}`,'_blank'));}}
function selRename(){{
  if(sel.size===1){{
    const id=[...sel][0];
    openRename(id,document.querySelector(`[data-id="${{id}}"]`)?.dataset.name||'');
  }} else toast('Select one item to rename','warn');
}}
function selMove(){{if(sel.size){{moveIds=[...sel];openMoveModal();}}}}
function selDel(){{
  if(sel.size){{
    delIds=[...sel];
    const name=document.querySelector(`[data-id="${{[...sel][0]}}"]`)?.dataset.name||'';
    document.getElementById('del-msg').textContent=sel.size===1?`Delete "${{name}}"?`:`Delete ${{sel.size}} items?`;
    openModal('delete');
  }}
}}

function openRename(id,name){{
  renameId=id;
  document.getElementById('i-rename').value=name;
  openModal('rename');
  setTimeout(()=>document.getElementById('i-rename').select(),60);
}}
async function doRename(){{
  const name=document.getElementById('i-rename').value.trim();if(!name)return;
  closeModal('rename');bar(true);
  const r=await fetch(`/api/rename/${{renameId}}`,{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{name}})}});
  bar(false);r.ok?toast('Renamed','ok'):toast('Failed','err');load();
}}

async function doDelete(){{
  closeModal('delete');bar(true);
  await Promise.all(delIds.map(id=>fetch(`/api/delete/${{id}}`,{{method:'POST'}})));
  bar(false);toast('Deleted','ok');clearSel();load();
}}

async function openMoveModal(){{
  openModal('move');
  const el=document.getElementById('move-tree');
  el.innerHTML='<div style="padding:16px;text-align:center;color:var(--text3);font-size:14px">Loading...</div>';
  const r=await fetch('/api/folders_tree');
  const d=await r.json();
  el.innerHTML=`<div class="fti" data-fid="" onclick="pickTree(this)">${{IC.folder}} Root</div>`+
    (d.folders||[]).map(f=>`<div class="fti" data-fid="${{f}}" onclick="pickTree(this)">&nbsp;&nbsp;${{IC.folder}} ${{f}}</div>`).join('');
}}
function pickTree(el){{el.closest('.ftree').querySelectorAll('.fti').forEach(e=>e.classList.remove('sel'));el.classList.add('sel');}}
async function confirmMove(){{
  const s=document.querySelector('#move-tree .fti.sel');if(!s){{toast('Select a folder','warn');return;}}
  closeModal('move');bar(true);
  await Promise.all(moveIds.map(id=>fetch(`/api/move/${{id}}`,{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{folder:s.dataset.fid}})}})));
  bar(false);toast('Moved','ok');clearSel();load();
}}

// New Folder modal
async function openMkdirModal(){{
  document.getElementById('i-mkdir').value='';
  // populate parent selector
  const sel2=document.getElementById('i-mkdir-parent');
  sel2.innerHTML='<option value="">— Root —</option>';
  try{{
    const r=await fetch('/api/folders_tree');
    const d=await r.json();
    (d.folders||[]).forEach(f=>{{sel2.innerHTML+=`<option value="${{f}}">${{f}}</option>`;}});
  }}catch(e){{}}
  openModal('mkdir');
  setTimeout(()=>document.getElementById('i-mkdir').focus(),60);
}}
async function doMkdir(){{
  const name=document.getElementById('i-mkdir').value.trim();if(!name)return;
  const parent=document.getElementById('i-mkdir-parent').value||null;
  closeModal('mkdir');bar(true);
  const r=await fetch('/api/mkdir',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{name,parent}})}});
  bar(false);r.ok?toast('Folder created','ok'):toast('Failed','err');
  load(); location.reload(); // refresh sidebar too
}}

// FAB — identical to GDrive webui
function toggleFab(){{
  fabOpen=!fabOpen;
  const btn=document.getElementById('fab-btn');
  const opts=document.getElementById('fab-opts');
  if(fabOpen){{
    btn.classList.add('open'); opts.style.display='flex';
    opts.innerHTML=`
      <div class="fab-opt" onclick="closeFab();openMkdirModal()">
        ${{IC.folder.replace('width="32"','width="22"').replace('height="32"','height="22"')}} <span>New Folder</span>
      </div>
      <div class="fab-opt" onclick="closeFab();openModal('upload')">
        {_icon("upload",22)} <span>Upload File</span>
      </div>`;
  }} else {{ closeFab(); }}
}}
function closeFab(){{
  fabOpen=false;
  document.getElementById('fab-btn').classList.remove('open');
  document.getElementById('fab-opts').style.display='none';
}}
document.addEventListener('click',e=>{{
  if(fabOpen&&!document.getElementById('fab').contains(e.target)) closeFab();
}});

// Upload
const dz=document.getElementById('dz');
if(dz){{
  dz.addEventListener('dragover',e=>{{e.preventDefault();dz.classList.add('dragover');}});
  dz.addEventListener('dragleave',()=>dz.classList.remove('dragover'));
  dz.addEventListener('drop',e=>{{e.preventDefault();dz.classList.remove('dragover');addFiles(e.dataTransfer.files);}});
}}
function addFiles(flist){{
  [...flist].forEach(f=>{{
    const id='u'+Date.now()+Math.random().toString(36).slice(2);
    uploadQ.push({{id,file:f,status:'pending'}});
    const el=document.createElement('div');el.className='uitem';el.id=id;
    el.innerHTML=`<div class="uitem-top"><span>${{getIco(f.type.split('/')[0]||'file')}}</span><span class="uname">${{f.name}}</span><span class="ust" id="${{id}}-st">Pending</span></div><div class="ubar"><div class="ufill" id="${{id}}-f"></div></div>`;
    document.getElementById('ulist').appendChild(el);
  }});
  document.getElementById('fi').value='';
}}
async function startUpload(){{
  if(!uploadQ.length){{toast('No files selected','warn');return;}}
  document.getElementById('ubtn').disabled=true;
  for(const item of uploadQ){{
    if(item.status!=='pending')continue;
    const st=document.getElementById(item.id+'-st');
    const fill=document.getElementById(item.id+'-f');
    st.textContent='Uploading...';st.style.color='var(--accent)';
    try{{
      await new Promise((res,rej)=>{{
        const xhr=new XMLHttpRequest();xhr.open('POST','/api/upload');
        xhr.upload.onprogress=e=>{{if(e.lengthComputable){{const p=Math.round(e.loaded/e.total*100);fill.style.width=p+'%';st.textContent=p+'%';}}}};
        xhr.onload=()=>{{if(xhr.status<300){{fill.style.width='100%';fill.style.background='var(--green)';st.textContent='Done';st.style.color='var(--green)';item.status='done';res();}}else{{st.textContent='Error';st.style.color='var(--red)';item.status='err';rej();}}}};
        xhr.onerror=()=>{{st.textContent='Error';st.style.color='var(--red)';rej();}};
        const fd=new FormData();fd.append('file',item.file);fd.append('folder',currentFolder||'');
        xhr.send(fd);
      }});
    }}catch(e){{item.status='err';}}
  }}
  document.getElementById('ubtn').disabled=false;
  const done=uploadQ.filter(x=>x.status==='done').length;
  if(done) toast(`Uploaded ${{done}} file${{done>1?'s':''}}`, 'ok');
  closeModal('upload');uploadQ=[];document.getElementById('ulist').innerHTML='';
  load();
}}

// Search
function doNavSearch(){{
  const q=document.getElementById('nav-search-input').value.trim();if(!q)return;
  document.getElementById('i-search').value=q;
  document.getElementById('search-res').innerHTML='';
  openModal('search'); doSearch();
}}
function onNavSearchInput(v){{}}
function openSearchModal(){{
  document.getElementById('i-search').value='';
  document.getElementById('search-res').innerHTML='';
  openModal('search');
  setTimeout(()=>document.getElementById('i-search').focus(),60);
}}
async function doSearch(){{
  const q=document.getElementById('i-search').value.trim();if(!q)return;
  const el=document.getElementById('search-res');
  el.innerHTML='<div style="padding:16px;text-align:center;color:var(--text3);font-size:14px">Searching...</div>';
  const r=await fetch(`/api/search?q=${{encodeURIComponent(q)}}`);
  const d=await r.json();
  if(!d.files||!d.files.length){{
    el.innerHTML=`<div style="padding:20px;text-align:center;color:var(--text3);font-size:14px">No results for "${{q}}"</div>`;return;
  }}
  el.innerHTML=d.files.map(f=>`<div class="sri" onclick="closeModal('search');openPreview('${{f._id}}','${{f.file_type}}','${{f.file_name.replace(/'/g,"&#39;")}}')">
    <div class="sri-icon">${{getIco(f.file_type)}}</div>
    <div class="sri-info">
      <div class="sri-name">${{f.file_name}}</div>
      <div class="sri-meta"><span class="sri-size">${{sz(f.file_size)}} · ${{f.file_type}}</span>
        <span class="sri-date">${{dt(f.message_date)}}</span></div>
    </div></div>`).join('');
}}

// Preview
function openPreview(id,ft,name){{
  _pvId=id;
  const ov=document.getElementById('preview-overlay');
  document.getElementById('preview-title').textContent=name||'Preview';
  const body=document.getElementById('preview-body');
  const sp=document.getElementById('preview-spinner');
  [...body.children].forEach(c=>{{if(c!==sp)c.remove();}});
  sp.style.display='flex'; ov.classList.add('open');
  const src=`/api/preview/${{id}}`;
  const hide=()=>sp.style.display='none';
  if(ft==='photo'){{
    const img=document.createElement('img');img.onload=hide;img.onerror=()=>{{hide();showUnsupported(name);}};img.src=src;body.appendChild(img);
  }} else if(ft==='video'||ft==='video_note'){{
    const v=document.createElement('video');v.controls=true;v.autoplay=true;v.style.cssText='max-width:100%;max-height:100%';v.oncanplay=hide;v.onerror=()=>{{hide();showUnsupported(name);}};v.src=src;body.appendChild(v);
  }} else if(ft==='audio'||ft==='voice'){{
    hide();const w=document.createElement('div');w.style.cssText='display:flex;flex-direction:column;align-items:center;gap:20px;padding:40px 24px';
    w.innerHTML=`<div style="font-size:80px">🎵</div><div style="font-size:16px;font-weight:600;color:var(--text);text-align:center;max-width:280px">${{name}}</div><audio controls autoplay style="width:100%;max-width:340px"><source src="${{src}}"></audio>`;body.appendChild(w);
  }} else {{ hide(); showUnsupported(name); }}
}}
function showUnsupported(name){{
  const body=document.getElementById('preview-body');
  const d=document.createElement('div');d.id='preview-unsupported';
  d.innerHTML=`<div class="pu-icon-wrap">${{IC.file}}</div><h3>Can't preview this file</h3>
    <p>Download it to open locally.</p>
    <button class="pu-dl-btn" onclick="previewDownload()">{_icon("download",18)} Download</button>`;
  body.appendChild(d);
}}
function closePreview(){{
  const ov=document.getElementById('preview-overlay');ov.classList.remove('open');
  const body=document.getElementById('preview-body');const sp=document.getElementById('preview-spinner');
  const v=body.querySelector('video');if(v){{v.pause();v.src='';}}
  const a=body.querySelector('audio');if(a){{a.pause();a.src='';}}
  [...body.children].forEach(c=>{{if(c!==sp)c.remove();}});
  sp.style.display='none';_pvId=null;
}}
function previewDownload(){{if(_pvId)dlFile(_pvId);}}

document.addEventListener('keydown',e=>{{
  if(e.key==='Escape'){{
    const ov=document.getElementById('preview-overlay');
    if(ov&&ov.classList.contains('open')){{closePreview();return;}}
    document.querySelectorAll('.moverlay.open').forEach(m=>m.classList.remove('open'));
    clearSel();closeFab();
  }}
  if(e.key==='Enter'){{
    if(document.getElementById('m-rename').classList.contains('open'))doRename();
    else if(document.getElementById('m-mkdir').classList.contains('open'))doMkdir();
    else if(document.getElementById('m-search').classList.contains('open'))doSearch();
  }}
}});
</script>""", "My Files")


# ─── API ───────────────────────────────────────────────────────────────────────

@require_auth
async def api_files(request: web.Request) -> web.Response:
    uid         = request["uid"]
    files_col   = request.app["files_col"]
    folders_col = request.app["folders_col"]
    folder      = request.rel_url.query.get("folder") or None

    # Sub-folders at this level
    sub_cursor = folders_col.find({"user_id": uid, "parent": folder}).sort("name", 1)
    sub_folders = [{"name": d["name"]} for d in await sub_cursor.to_list(100)]

    # Files in this folder
    q = {"user_id": uid}
    if folder:
        q["folders"] = folder
    else:
        # root = files not in any folder OR all files
        pass  # show all files at root

    cursor = files_col.find(q).sort("message_date", -1).limit(300)
    raw    = await cursor.to_list(300)

    def ser(f):
        f["_id"] = str(f["_id"])
        if "message_date" in f and hasattr(f["message_date"], "isoformat"):
            f["message_date"] = f["message_date"].isoformat()
        f.setdefault("folders", f.pop("tags", []))
        return f

    return web.json_response({"folders": sub_folders, "files": [ser(f) for f in raw]})


@require_auth
async def api_folders_tree(request: web.Request) -> web.Response:
    uid         = request["uid"]
    folders_col = request.app["folders_col"]
    cursor = folders_col.find({"user_id": uid}).sort("name", 1)
    docs   = await cursor.to_list(200)
    return web.json_response({"folders": [d["name"] for d in docs]})


@require_auth
async def api_mkdir(request: web.Request) -> web.Response:
    uid         = request["uid"]
    folders_col = request.app["folders_col"]
    body   = await request.json()
    name   = body.get("name", "").strip()
    parent = body.get("parent") or None
    if not name:
        raise web.HTTPBadRequest(reason="Name required")
    existing = await folders_col.find_one({"user_id": uid, "name": name, "parent": parent})
    if existing:
        return web.json_response({"ok": True, "msg": "already exists"})
    await folders_col.insert_one({"user_id": uid, "name": name, "parent": parent,
                                   "created_at": datetime.utcnow()})
    return web.json_response({"ok": True})


@require_auth
async def api_rename(request: web.Request) -> web.Response:
    uid       = request["uid"]
    fid       = request.match_info["fid"]
    files_col = request.app["files_col"]
    body      = await request.json()
    name      = body.get("name", "").strip()
    if not name: raise web.HTTPBadRequest(reason="Name required")
    await files_col.update_one({"_id": ObjectId(fid), "user_id": uid}, {"$set": {"file_name": name}})
    return web.json_response({"ok": True})


@require_auth
async def api_delete(request: web.Request) -> web.Response:
    uid       = request["uid"]
    fid       = request.match_info["fid"]
    files_col = request.app["files_col"]
    await files_col.delete_one({"_id": ObjectId(fid), "user_id": uid})
    return web.json_response({"ok": True})


@require_auth
async def api_move(request: web.Request) -> web.Response:
    uid       = request["uid"]
    fid       = request.match_info["fid"]
    files_col = request.app["files_col"]
    body      = await request.json()
    folder    = body.get("folder") or None
    update    = {"$set": {"folders": [folder]}} if folder else {"$set": {"folders": []}}
    await files_col.update_one({"_id": ObjectId(fid), "user_id": uid}, update)
    return web.json_response({"ok": True})


@require_auth
async def api_search(request: web.Request) -> web.Response:
    uid       = request["uid"]
    q         = request.rel_url.query.get("q", "").strip()
    files_col = request.app["files_col"]
    if not q: return web.json_response({"files": []})
    cursor = files_col.find({"user_id": uid, "$or": [
        {"file_name": {"$regex": q, "$options": "i"}},
        {"folders":   {"$regex": q, "$options": "i"}},
        {"tags":      {"$regex": q, "$options": "i"}},
    ]}).sort("message_date", -1).limit(50)
    raw = await cursor.to_list(50)
    def ser(f):
        f["_id"] = str(f["_id"])
        if "message_date" in f and hasattr(f["message_date"], "isoformat"):
            f["message_date"] = f["message_date"].isoformat()
        f.setdefault("folders", f.pop("tags", []))
        return f
    return web.json_response({"files": [ser(f) for f in raw]})


@require_auth
async def api_download(request: web.Request) -> web.Response:
    """Stream file via Pyrogram userbot (supports large files > 20 MB)."""
    import aiohttp as _aiohttp
    uid       = request["uid"]
    fid       = request.match_info["fid"]
    files_col = request.app["files_col"]
    pyro      = request.app.get("pyrogram_client")
    bot_inst  = request.app.get("bot_instance")

    try:
        doc = await files_col.find_one({"_id": ObjectId(fid), "user_id": uid})
        if not doc: raise web.HTTPNotFound(reason="File not found")

        tg_file_id = doc["file_id"]
        file_name  = doc.get("file_name", "file")
        storage_ch = doc.get("storage_channel_id")
        storage_mid= doc.get("storage_message_id")

        # --- Try Pyrogram first (large files) ---
        if pyro and storage_ch and storage_mid:
            try:
                import tempfile, os
                # Download via pyrogram to temp file then stream
                msg = await pyro.get_messages(storage_ch, storage_mid)
                tmp = tempfile.NamedTemporaryFile(delete=False, suffix="_" + file_name)
                tmp.close()
                await pyro.download_media(msg, file_name=tmp.name)
                file_size = os.path.getsize(tmp.name)
                resp = web.StreamResponse(headers={
                    "Content-Disposition": f'attachment; filename="{file_name}"',
                    "Content-Length": str(file_size),
                    "Content-Type": "application/octet-stream",
                })
                await resp.prepare(request)
                with open(tmp.name, "rb") as f:
                    while True:
                        chunk = f.read(65536)
                        if not chunk: break
                        await resp.write(chunk)
                await resp.write_eof()
                os.unlink(tmp.name)
                return resp
            except Exception as e:
                logger.warning(f"Pyrogram download failed, falling back to Bot API: {e}")

        # --- Fallback: Bot API (works for files < 20 MB) ---
        if not bot_inst: raise web.HTTPServiceUnavailable(reason="No bot available")
        import os
        tg_file  = await bot_inst.get_file(tg_file_id)
        dl_url   = f"https://api.telegram.org/file/bot{os.getenv('BOT_TOKEN')}/{tg_file.file_path}"
        range_h  = request.headers.get("Range")
        headers  = {"Range": range_h} if range_h else {}
        async with _aiohttp.ClientSession() as session:
            async with session.get(dl_url, headers=headers) as gr:
                resp_h = {
                    "Content-Disposition": f'attachment; filename="{file_name}"',
                    "Content-Type": gr.headers.get("Content-Type", "application/octet-stream"),
                }
                for h in ("Content-Length","Content-Range","Accept-Ranges"):
                    if h in gr.headers: resp_h[h] = gr.headers[h]
                resp = web.StreamResponse(status=gr.status, headers=resp_h)
                await resp.prepare(request)
                async for chunk in gr.content.iter_chunked(65536):
                    await resp.write(chunk)
                await resp.write_eof()
                return resp
    except web.HTTPException: raise
    except Exception as e:
        logger.error(f"api_download: {e}", exc_info=True)
        raise web.HTTPInternalServerError(reason=str(e))


@require_auth
async def api_preview(request: web.Request) -> web.Response:
    """Inline preview — same logic as download but Content-Disposition: inline."""
    import aiohttp as _aiohttp
    uid       = request["uid"]
    fid       = request.match_info["fid"]
    files_col = request.app["files_col"]
    bot_inst  = request.app.get("bot_instance")

    try:
        doc = await files_col.find_one({"_id": ObjectId(fid), "user_id": uid})
        if not doc: raise web.HTTPNotFound()
        tg_file_id = doc["file_id"]
        file_name  = doc.get("file_name", "file")
        ft         = doc.get("file_type", "document")
        mime_map   = {"photo":"image/jpeg","video":"video/mp4","video_note":"video/mp4",
                      "audio":"audio/mpeg","voice":"audio/ogg"}
        ct = mime_map.get(ft, "application/octet-stream")
        ext_map = {"jpg":"image/jpeg","jpeg":"image/jpeg","png":"image/png","gif":"image/gif",
                   "webp":"image/webp","mp4":"video/mp4","mp3":"audio/mpeg","ogg":"audio/ogg",
                   "m4a":"audio/mp4","pdf":"application/pdf"}
        ext = file_name.rsplit(".",1)[-1].lower() if "." in file_name else ""
        if ext in ext_map: ct = ext_map[ext]

        if not bot_inst: raise web.HTTPServiceUnavailable()
        import os
        tg_file = await bot_inst.get_file(tg_file_id)
        dl_url  = f"https://api.telegram.org/file/bot{os.getenv('BOT_TOKEN')}/{tg_file.file_path}"
        range_h = request.headers.get("Range")
        headers = {"Range": range_h} if range_h else {}
        async with _aiohttp.ClientSession() as session:
            async with session.get(dl_url, headers=headers) as gr:
                resp_h = {
                    "Content-Disposition": f'inline; filename="{file_name}"',
                    "Content-Type": gr.headers.get("Content-Type", ct),
                    "Accept-Ranges": "bytes",
                }
                for h in ("Content-Length","Content-Range"):
                    if h in gr.headers: resp_h[h] = gr.headers[h]
                resp = web.StreamResponse(status=gr.status, headers=resp_h)
                await resp.prepare(request)
                async for chunk in gr.content.iter_chunked(65536):
                    await resp.write(chunk)
                await resp.write_eof()
                return resp
    except web.HTTPException: raise
    except Exception as e:
        logger.error(f"api_preview: {e}", exc_info=True)
        raise web.HTTPInternalServerError(reason=str(e))


@require_auth
async def api_upload(request: web.Request) -> web.Response:
    """Receive uploaded file, forward it to the storage Telegram channel via bot."""
    import tempfile, os
    uid       = request["uid"]
    bot_inst  = request.app.get("bot_instance")
    files_col = request.app["files_col"]
    folders_col= request.app["folders_col"]
    storage_ch = os.getenv("STORAGE_CHANNEL_ID")

    if not bot_inst or not storage_ch:
        raise web.HTTPServiceUnavailable(reason="Bot not available")

    try:
        reader      = await request.multipart()
        folder_name = None
        file_data   = None
        file_name   = "upload"
        async for part in reader:
            if part.name == "folder":
                folder_name = (await part.read_chunk()).decode().strip() or None
            elif part.name == "file":
                file_name = part.filename or "upload"
                chunks = []
                while True:
                    chunk = await part.read_chunk(65536)
                    if not chunk: break
                    chunks.append(chunk)
                file_data = b"".join(chunks)

        if file_data is None:
            raise web.HTTPBadRequest(reason="No file")

        # Save to temp, send via bot
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix="_" + file_name)
        tmp.write(file_data); tmp.close()

        sent = await bot_inst.send_document(int(storage_ch), FSInputFile(tmp.name, filename=file_name))
        os.unlink(tmp.name)

        tg_fid = sent.document.file_id
        fsize  = sent.document.file_size

        folders_list = [folder_name] if folder_name else []
        res = await files_col.insert_one({
            "user_id": uid, "file_id": tg_fid,
            "file_name": file_name, "file_size": fsize,
            "file_type": "document", "folders": folders_list,
            "message_date": datetime.utcnow(),
            "storage_message_id": sent.message_id,
            "storage_channel_id": int(storage_ch),
        })
        if folder_name:
            await folders_col.update_one(
                {"user_id": uid, "name": folder_name, "parent": None},
                {"$setOnInsert": {"created_at": datetime.utcnow()}}, upsert=True
            )
        return web.json_response({"ok": True, "id": str(res.inserted_id)})

    except web.HTTPException: raise
    except Exception as e:
        logger.error(f"api_upload: {e}", exc_info=True)
        raise web.HTTPInternalServerError(reason=str(e))


# ─── App factory ───────────────────────────────────────────────────────────────

def create_app(files_collection, folders_collection, settings_collection,
               bot_instance=None, pyrogram_client=None) -> web.Application:
    app = web.Application(client_max_size=2 * 1024 * 1024 * 1024)  # 2 GB
    app["files_col"]    = files_collection
    app["folders_col"]  = folders_collection
    app["settings_col"] = settings_collection
    app["bot_instance"] = bot_instance
    app["pyrogram_client"] = pyrogram_client

    app.router.add_route("GET",  "/",                   handle_login)
    app.router.add_route("POST", "/",                   handle_login)
    app.router.add_get("/logout",                       handle_logout)
    app.router.add_get("/files",                        handle_files)
    app.router.add_get("/api/files",                    api_files)
    app.router.add_get("/api/folders_tree",             api_folders_tree)
    app.router.add_post("/api/mkdir",                   api_mkdir)
    app.router.add_post("/api/rename/{fid}",            api_rename)
    app.router.add_post("/api/delete/{fid}",            api_delete)
    app.router.add_post("/api/move/{fid}",              api_move)
    app.router.add_get("/api/search",                   api_search)
    app.router.add_get("/api/download/{fid}",           api_download)
    app.router.add_get("/api/preview/{fid}",            api_preview)
    app.router.add_post("/api/upload",                  api_upload)

    return app
