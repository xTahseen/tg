"""
SecureBox Web UI — file manager interface
Adapted from Google Drive bot app.py design, wired to MongoDB + Telegram file storage.
"""

import asyncio
import hashlib
import hmac
import json
import logging
import time
from functools import wraps
from datetime import datetime

from aiohttp import web
from bson import ObjectId

logger = logging.getLogger(__name__)

# ─── Auth helpers ──────────────────────────────────────────────────────────────

def _get_secret():
    import os
    return os.getenv("WEBUI_SECRET_KEY", "securebox-secret-key-change-me")

def _sign(payload: dict) -> str:
    import base64
    data = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    sig = hmac.new(_get_secret().encode(), data.encode(), hashlib.sha256).hexdigest()
    return f"{data}.{sig}"

def _verify(token: str):
    try:
        import base64
        data, sig = token.rsplit(".", 1)
        expected = hmac.new(_get_secret().encode(), data.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(base64.urlsafe_b64decode(data).decode())
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None

def _make_token(uid: int) -> str:
    return _sign({"uid": uid, "exp": time.time() + 86400 * 7})

def _hash_pw(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def _fmt_size(b):
    if not b: return "0 B"
    b = int(b)
    if b < 1024: return f"{b} B"
    if b < 1048576: return f"{b/1024:.1f} KB"
    if b < 1073741824: return f"{b/1048576:.1f} MB"
    return f"{b/1073741824:.2f} GB"

def require_auth(handler):
    @wraps(handler)
    async def wrapper(request: web.Request):
        tok = request.cookies.get("session")
        payload = _verify(tok) if tok else None
        if not payload:
            if request.path.startswith("/api/"):
                raise web.HTTPUnauthorized(reason="Not authenticated")
            raise web.HTTPFound("/")
        request["uid"] = payload["uid"]
        return await handler(request)
    return wrapper

# ─── SVG Icons ─────────────────────────────────────────────────────────────────

def _icon(name: str, size: int = 20, cls: str = "", bg_color: str = None) -> str:
    cls_attr = f' class="{cls}"' if cls else ""
    icons = {
        "folder":      '<path d="M2.25 12.75V12A2.25 2.25 0 014.5 9.75h15A2.25 2.25 0 0121.75 12v.75m-8.69-6.44l-2.12-2.12a1.5 1.5 0 00-1.061-.44H4.5A2.25 2.25 0 002.25 6v12a2.25 2.25 0 002.25 2.25h15A2.25 2.25 0 0021.75 18V9a2.25 2.25 0 00-2.25-2.25h-5.379a1.5 1.5 0 01-1.06-.44z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
        "file":        '<path d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m2.25 0H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
        "image":       '<path d="M2.25 15.75l5.159-5.159a2.25 2.25 0 013.182 0l5.159 5.159m-1.5-1.5l1.409-1.409a2.25 2.25 0 013.182 0l2.909 2.909m-18 3.75h16.5a1.5 1.5 0 001.5-1.5V6a1.5 1.5 0 00-1.5-1.5H3.75A1.5 1.5 0 002.25 6v12a1.5 1.5 0 001.5 1.5zm10.5-11.25h.008v.008h-.008V8.25zm.375 0a.375.375 0 11-.75 0 .375.375 0 01.75 0z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
        "video":       '<path d="M15.75 10.5l4.72-4.72a.75.75 0 011.28.53v11.38a.75.75 0 01-1.28.53l-4.72-4.72M4.5 18.75h9a2.25 2.25 0 002.25-2.25v-9a2.25 2.25 0 00-2.25-2.25h-9A2.25 2.25 0 002.25 7.5v9a2.25 2.25 0 002.25 2.25z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
        "audio":       '<path d="M9 9l10.5-3m0 6.553v3.75a2.25 2.25 0 01-1.632 2.163l-1.32.377a1.803 1.803 0 11-.99-3.467l2.31-.66a2.25 2.25 0 001.632-2.163zm0 0V2.25L9 5.25v10.303m0 0v3.75a2.25 2.25 0 01-1.632 2.163l-1.32.377a1.803 1.803 0 01-.99-3.467l2.31-.66A2.25 2.25 0 009 15.553z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
        "home":        '<path d="M2.25 12l8.954-8.955a1.126 1.126 0 011.591 0L21.75 12M4.5 9.75v10.125c0 .621.504 1.125 1.125 1.125H9.75v-4.875c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125V21h4.125c.621 0 1.125-.504 1.125-1.125V9.75M8.25 21h8.25" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "search":      '<path d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 15.803 7.5 7.5 0 0015.803 15.803z" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "back":        '<path d="M10.5 19.5L3 12m0 0l7.5-7.5M3 12h18" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "plus":        '<path d="M12 4.5v15m7.5-7.5h-15" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "close":       '<path d="M6 18L18 6M6 6l12 12" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "refresh":     '<path d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0l3.181 3.183a8.25 8.25 0 0013.803-3.7M4.031 9.865a8.25 8.25 0 0113.803-3.7l3.181 3.182m0-4.991v4.99" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "download":    '<path d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "delete":      '<path d="M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 01-2.244 2.077H8.084a2.25 2.25 0 01-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 00-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 013.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 00-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 00-7.5 0" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "rename":      '<path d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L6.832 19.82a4.5 4.5 0 01-1.897 1.13l-2.685.8.8-2.685a4.5 4.5 0 011.13-1.897L16.863 4.487zm0 0L19.5 7.125" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "move":        '<path d="M7.5 21L3 16.5m0 0L7.5 12M3 16.5h13.5m0-13.5L21 7.5m0 0L16.5 12M21 7.5H7.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "signout":     '<path d="M15.75 9V5.25A2.25 2.25 0 0013.5 3h-6a2.25 2.25 0 00-2.25 2.25v13.5A2.25 2.25 0 007.5 21h6a2.25 2.25 0 002.25-2.25V15M12 9l-3 3m0 0l3 3m-3-3h12.75" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "check":       '<path d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "alert":       '<path d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "login_arrow": '<path d="M15.75 9V5.25A2.25 2.25 0 0013.5 3h-6a2.25 2.25 0 00-2.25 2.25v13.5A2.25 2.25 0 007.5 21h6a2.25 2.25 0 002.25-2.25V15m3 0l3-3m0 0l-3-3m3 3H9" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "lock":        '<path d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "tag":         '<path d="M9.568 3H5.25A2.25 2.25 0 003 5.25v4.318c0 .597.237 1.17.659 1.591l9.581 9.581c.699.699 1.78.872 2.607.33a18.095 18.095 0 005.223-5.223c.542-.827.369-1.908-.33-2.607L11.16 3.66A2.25 2.25 0 009.568 3z" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/><path d="M6 6h.008v.008H6V6z" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "newfolder":   '<path d="M12 10.5v6m3-3H9m4.06-7.19l-2.12-2.12a1.5 1.5 0 00-1.061-.44H4.5A2.25 2.25 0 002.25 6v12a2.25 2.25 0 002.25 2.25h15A2.25 2.25 0 0021.75 18V9a2.25 2.25 0 00-2.25-2.25h-5.379a1.5 1.5 0 01-1.06-.44z" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
    }
    path = icons.get(name, icons["file"])
    svg = f'<svg{cls_attr} width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">{path}</svg>'
    if bg_color:
        return f'<div class="icon-bg" style="background-color:{bg_color}">{svg}</div>'
    return svg

def _file_icon(file_type: str, size: int = 20) -> str:
    t = file_type or ""
    if t == "photo": return _icon("image", size, "", "#a78bfa")
    if t == "video": return _icon("video", size, "", "#f87171")
    if t == "audio": return _icon("audio", size, "", "#e55835")
    if t == "voice": return _icon("audio", size, "", "#fb923c")
    if t == "video_note": return _icon("video", size, "", "#f87171")
    if t == "sticker": return _icon("image", size, "", "#818cf8")
    return _icon("file", size, "", "#607d8b")

# ─── CSS ───────────────────────────────────────────────────────────────────────

_CSS = """
:root {
  --bg: #000000; --header: #171717; --surface: #1a1a1a; --surface2: #222222;
  --surface3: #2a2a2a; --border: #2c2c2c; --border2: #3a3a3a;
  --accent: #0483c3; --accent2: #0369a1; --accent-dim: rgba(4,131,195,.13);
  --green: #22c55e; --red: #ef4444; --yellow: #f59e0b;
  --fab: #ffb200; --fab2: #e6a000;
  --text: #f0f0f0; --text2: #a0a0a0; --text3: #555;
  --folder: #0483c3; --r4: 4px; --r8: 8px; --r12: 12px; --r16: 16px;
  --sans: 'Google Sans', 'Roboto', 'Segoe UI', system-ui, -apple-system, sans-serif;
  --shadow: 0 8px 32px rgba(0,0,0,.6);
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { height: 100%; -webkit-text-size-adjust: 100%; }
body { background: var(--bg); color: var(--text); font-family: var(--sans);
  font-size: 15px; height: 100%; -webkit-font-smoothing: antialiased; overflow-x: hidden; }
a { color: var(--accent); text-decoration: none; }
::-webkit-scrollbar { width: 4px; height: 4px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 2px; }

#bar { position: fixed; top: 0; left: 0; right: 0; height: 3px; background: var(--accent);
  transform: scaleX(0); transform-origin: left; transition: transform .4s; z-index: 9999; opacity: 0; }
#bar.on  { transform: scaleX(.7); opacity: 1; }
#bar.done { transform: scaleX(1); opacity: 0; transition: transform .3s, opacity .4s .2s; }

#toast { position: fixed; bottom: 90px; left: 50%; transform: translateX(-50%) translateY(20px);
  background: var(--surface2); border: 1px solid var(--border2); color: var(--text);
  border-radius: 24px; padding: 12px 22px; font-size: 14px; z-index: 9999; opacity: 0;
  pointer-events: none; transition: all .22s ease; white-space: nowrap; box-shadow: var(--shadow); }
#toast.show { transform: translateX(-50%) translateY(0); opacity: 1; }
#toast.ok   { border-color: var(--green); color: var(--green); }
#toast.err  { border-color: var(--red); color: var(--red); }
#toast.warn { border-color: var(--yellow); color: var(--yellow); }

.btn { display: inline-flex; align-items: center; gap: 8px; border: none;
  border-radius: var(--r8); cursor: pointer; font-size: 14px; font-weight: 500;
  font-family: var(--sans); transition: all .15s; white-space: nowrap; padding: 0 16px; height: 40px; }
.btn:active { transform: scale(.97); }
.btn-primary { background: var(--accent); color: #fff; }
.btn-primary:hover { background: var(--accent2); }
.btn-ghost { background: transparent; color: var(--text2); border: 1px solid var(--border2); }
.btn-ghost:hover { background: var(--surface3); color: var(--text); }
.btn-danger { background: rgba(239,68,68,.15); color: var(--red); border: 1px solid rgba(239,68,68,.3); }
.btn-danger:hover { background: rgba(239,68,68,.25); }
.btn-icon { width: 40px; height: 40px; padding: 0; border-radius: var(--r8);
  background: transparent; color: var(--text2); border: none; justify-content: center;
  display: inline-flex; align-items: center; }
.btn-icon:hover { background: var(--surface3); color: var(--text); }
.btn-sm { height: 34px; padding: 0 13px; font-size: 13px; }
.btn-wide { width: 100%; justify-content: center; }

input, select { background: var(--surface3); color: var(--text); border: 1px solid var(--border);
  border-radius: var(--r8); padding: 11px 14px; font-size: 15px; font-family: var(--sans);
  width: 100%; outline: none; transition: border-color .15s, box-shadow .15s; }
input:focus, select:focus { border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-dim); }
input::placeholder { color: var(--text3); }

nav { background: #171717; padding: 0 14px; display: flex; align-items: center; gap: 10px;
  height: 58px; position: sticky; top: 0; z-index: 200; border-bottom: 1px solid var(--border); }
.nav-logo { display: flex; align-items: center; gap: 10px; text-decoration: none; flex-shrink: 0; }
.nav-logo-text { font-size: 18px; font-weight: 800; color: var(--text); letter-spacing: -.3px; }
.nav-logo-text span { color: var(--accent); }
.nav-center { flex: 1; display: flex; justify-content: center; padding: 0 8px; }
.nav-search-wrap { display: flex; align-items: center; gap: 8px;
  background: rgba(255,255,255,0.07); border: 1px solid rgba(255,255,255,0.1);
  border-radius: 24px; padding: 0 14px; height: 38px; width: 100%; max-width: 420px;
  transition: background .18s, border-color .18s, box-shadow .18s; }
.nav-search-wrap:focus-within { background: rgba(255,255,255,0.11); border-color: var(--accent);
  box-shadow: 0 0 0 3px var(--accent-dim); }
.nav-search-wrap svg { color: var(--text3); flex-shrink: 0; }
#nav-search-input { background: transparent; border: none; outline: none; color: var(--text);
  font-size: 14px; font-family: var(--sans); width: 100%; padding: 0; box-shadow: none; }
#nav-search-input::placeholder { color: var(--text3); }

.toolbar { display: flex; align-items: center; gap: 8px; padding: 10px 14px;
  background: #171717; flex-shrink: 0; min-height: 52px; border-bottom: 1px solid var(--border); }
.breadcrumb { display: flex; align-items: center; gap: 2px; flex: 1; min-width: 0;
  overflow-x: auto; overflow-y: hidden; scrollbar-width: none; -ms-overflow-style: none; }
.breadcrumb::-webkit-scrollbar { display: none; }
.bc-crumb { color: var(--text2); cursor: pointer; padding: 5px 8px; border-radius: var(--r4);
  font-size: 14px; white-space: nowrap; transition: all .1s; flex-shrink: 0; }
.bc-crumb:hover { background: var(--surface2); color: var(--text); }
.bc-crumb.last { color: var(--accent); cursor: default; font-weight: 600; }
.bc-crumb.last:hover { background: transparent; }
.bc-sep { color: var(--text3); flex-shrink: 0; font-size: 18px; padding: 0 2px; }
.filter-chips { display: flex; align-items: center; gap: 6px; overflow-x: auto; scrollbar-width: none; }
.filter-chips::-webkit-scrollbar { display: none; }
.chip { display: inline-flex; align-items: center; gap: 5px; padding: 5px 12px;
  border-radius: 20px; font-size: 12px; font-weight: 600; cursor: pointer; white-space: nowrap;
  border: 1px solid var(--border2); background: var(--surface2); color: var(--text2);
  transition: all .15s; }
.chip:hover { border-color: var(--accent); color: var(--accent); }
.chip.active { background: var(--accent-dim); border-color: var(--accent); color: var(--accent); }

.layout { display: flex; height: calc(100vh - 58px); overflow: hidden; }
.sidebar { width: 220px; flex-shrink: 0; background: var(--header);
  border-right: 1px solid var(--border); padding: 12px 8px;
  display: flex; flex-direction: column; gap: 2px; overflow-y: auto; }
.sb-item { display: flex; align-items: center; gap: 10px; padding: 11px 12px;
  border-radius: var(--r8); cursor: pointer; font-size: 14px; font-weight: 500;
  color: var(--text2); transition: all .12s; border: 1px solid transparent; }
.sb-item:hover { background: var(--surface2); color: var(--text); }
.sb-item.active { background: var(--accent-dim); color: var(--accent); border-color: rgba(4,131,195,.2); }
.sb-item svg { flex-shrink: 0; }
.sb-divider { height: 1px; background: var(--border); margin: 8px 4px; }
.sb-label { font-size: 11px; font-weight: 700; letter-spacing: .1em; text-transform: uppercase;
  color: var(--text3); padding: 8px 12px 3px; }
.sb-folder { display: flex; align-items: center; gap: 8px; padding: 8px 12px;
  border-radius: var(--r8); cursor: pointer; font-size: 13px; color: var(--text2);
  transition: all .12s; border: 1px solid transparent; }
.sb-folder:hover { background: var(--surface2); color: var(--text); }
.sb-folder.active { background: var(--accent-dim); color: var(--accent); }
.sb-folder-name { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

.main { flex: 1; display: flex; flex-direction: column; overflow: hidden; min-width: 0; }
.file-area { flex: 1; overflow-y: auto; padding-bottom: 100px; }

.file-item { display: flex; align-items: center; gap: 14px; padding: 10px 12px;
  border-bottom: 0.9px solid rgba(44,44,44,.6); cursor: pointer;
  transition: background .08s; position: relative; user-select: none; -webkit-user-select: none; }
.file-item:active { background: var(--surface2); }
.file-item.sel { background: rgba(4,131,195,.1); }
.file-item.sel .fi-cb { display: flex; }
.fi-cb { display: none; width: 20px; height: 20px; flex-shrink: 0;
  align-items: center; justify-content: center; }
body.select-mode .fi-cb { display: flex; }

.custom-cb { width: 20px; height: 20px; border-radius: 50%; border: 2px solid var(--border2);
  background: transparent; display: flex; align-items: center; justify-content: center;
  cursor: pointer; transition: all .18s ease; flex-shrink: 0; position: relative; }
.custom-cb::after { content: ''; width: 0; height: 0; border-radius: 50%;
  background: var(--accent); transition: all .15s ease; position: absolute; }
.custom-cb.checked { background: var(--accent); border-color: var(--accent);
  box-shadow: 0 2px 8px rgba(4,131,195,.4); }
.custom-cb.checked::after { content: ''; width: 7px; height: 4px; background: transparent;
  border-radius: 0; border-left: 2px solid #fff; border-bottom: 2px solid #fff;
  transform: rotate(-45deg) translateY(-1px); position: static; }
.custom-cb:not(.checked):hover { border-color: var(--accent); background: var(--accent-dim); }

.fi-icon { flex-shrink: 0; display: flex; align-items: center; justify-content: center; width: 46px; height: 46px; }
.icon-bg { display: flex; align-items: center; justify-content: center; width: 46px; height: 46px;
  border-radius: 50%; flex-shrink: 0; box-shadow: 0 2px 8px rgba(0,0,0,.3); }
.icon-bg svg { width: 24px; height: 24px; color: white; stroke: white; }
.fi-info { flex: 1; min-width: 0; overflow: hidden; }
.fi-name { font-size: 15px; font-weight: 400; color: var(--text);
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis; line-height: 1.3; }
.fi-meta { display: flex; justify-content: space-between; align-items: center; margin-top: 3px; width: 100%; }
.fi-size { font-size: 12px; color: var(--text3); }
.fi-date { font-size: 12px; color: var(--text3); margin-left: auto; padding-left: 8px; white-space: nowrap; }
.fi-folders { font-size: 11px; color: var(--accent); margin-top: 2px;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.fi-act { position: absolute; right: 10px; top: 50%; transform: translateY(-50%);
  opacity: 0; transition: opacity .15s; pointer-events: none; }
@media (hover: hover) { .file-item:hover .fi-act { opacity: 1; pointer-events: auto; } }

.empty { display: flex; flex-direction: column; align-items: center; justify-content: center;
  padding: 80px 24px; gap: 16px; color: var(--text3); }
.empty-icon { color: var(--text3); opacity: .35; }
.empty h3 { font-size: 20px; font-weight: 600; color: var(--text2); }
.empty p { font-size: 14px; }

.sk { background: linear-gradient(90deg,var(--surface) 25%,var(--surface3) 50%,var(--surface) 75%);
  background-size: 200% 100%; animation: sk 1.4s infinite; border-radius: var(--r4); }
@keyframes sk { 0% { background-position: 200% 0 } 100% { background-position: -200% 0 } }
.sk-n { height: 15px; width: 55%; } .sk-s { height: 12px; width: 30%; } .sk-i { height: 46px; width: 46px; border-radius: 50%; flex-shrink: 0; }

#fab { position: fixed; bottom: 24px; right: 20px; z-index: 400;
  display: flex; flex-direction: column; align-items: flex-end; gap: 12px; transition: bottom .3s ease; }
body.select-mode #fab { bottom: 96px; }
.fab-main { width: 58px; height: 58px; border-radius: 50%; background: var(--fab); color: #fff;
  border: none; display: flex; align-items: center; justify-content: center; cursor: pointer;
  box-shadow: 0 4px 20px rgba(255,178,0,.4); transition: all .2s; font-size: 28px; font-weight: 300; flex-shrink: 0; }
.fab-main:hover { background: var(--fab2); transform: scale(1.06); }
.fab-main:active { transform: scale(.96); }
.fab-main.open { transform: rotate(45deg); }
.fab-options { display: flex; flex-direction: column; align-items: flex-end; gap: 10px;
  transform-origin: bottom right; animation: fabIn .18s ease; }
@keyframes fabIn { from { opacity: 0; transform: scale(.85) translateY(10px); } }
.fab-opt { display: flex; align-items: center; gap: 10px; background: var(--surface2);
  border: 1px solid var(--border2); border-radius: 28px; padding: 10px 18px 10px 14px;
  cursor: pointer; font-size: 14px; font-weight: 600; color: var(--text);
  box-shadow: 0 4px 16px rgba(0,0,0,.5); transition: all .15s; white-space: nowrap; }
.fab-opt:hover { background: var(--surface3); border-color: var(--accent); color: var(--accent); }

#selbar { position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%) translateY(100px);
  background: var(--surface2); border: 1px solid var(--border2); border-radius: 36px;
  padding: 10px 14px; display: flex; align-items: center; gap: 6px;
  box-shadow: 0 8px 40px rgba(0,0,0,.7); z-index: 500; opacity: 0; pointer-events: none;
  transition: transform .28s cubic-bezier(.34,1.56,.64,1), opacity .18s;
  max-width: calc(100vw - 32px); }
#selbar.show { transform: translateX(-50%) translateY(0); opacity: 1; pointer-events: auto; }
#selcnt { font-size: 13px; color: var(--text2); padding: 0 4px; white-space: nowrap; }
.selbar-sep { width: 1px; height: 22px; background: var(--border2); margin: 0 2px; flex-shrink: 0; }
.sel-btn { display: flex; flex-direction: column; align-items: center; gap: 2px;
  background: transparent; border: none; cursor: pointer; padding: 6px 8px;
  border-radius: var(--r8); color: var(--text2); transition: all .12s; flex-shrink: 0; }
.sel-btn:hover { background: var(--surface3); color: var(--text); }
.sel-btn.danger { color: var(--red); }
.sel-btn.danger:hover { background: rgba(239,68,68,.15); }
.sel-btn span { font-size: 10px; font-weight: 600; white-space: nowrap; }
.sel-close { width: 30px; height: 30px; border-radius: 50%; background: var(--surface3);
  border: none; cursor: pointer; display: flex; align-items: center; justify-content: center;
  color: var(--text3); flex-shrink: 0; margin-left: 2px; }
.sel-close:hover { color: var(--text); background: var(--border2); }

.moverlay { display: none; position: fixed; inset: 0; background: rgba(0,0,0,.75);
  backdrop-filter: blur(6px); z-index: 1000; align-items: center; justify-content: center; padding: 16px; }
.moverlay.open { display: flex; }
.modal { background: var(--surface); border: 1px solid var(--border2); border-radius: var(--r16);
  padding: 22px 20px; width: 100%; max-width: 420px; box-shadow: var(--shadow);
  animation: mIn .2s ease; max-height: 88vh; overflow-y: auto; }
@keyframes mIn { from { transform: scale(.95) translateY(-8px); opacity: 0; } }
.modal-title { font-size: 16px; font-weight: 700; margin-bottom: 16px;
  display: flex; align-items: center; gap: 9px; color: var(--text); }
.fg { margin-bottom: 14px; }
.fg label { display: block; font-size: 11px; color: var(--text3); margin-bottom: 5px;
  text-transform: uppercase; letter-spacing: .05em; font-weight: 600; }
.macts { display: flex; gap: 8px; justify-content: flex-end; margin-top: 18px; }

#preview-overlay { display: none; position: fixed; inset: 0; z-index: 2000; background: #000; flex-direction: column; }
#preview-overlay.open { display: flex; }
#preview-bar { display: flex; align-items: center; gap: 10px; padding: 10px 14px;
  background: rgba(0,0,0,0.85); backdrop-filter: blur(12px);
  border-bottom: 1px solid rgba(255,255,255,0.07); flex-shrink: 0; min-height: 52px; }
#preview-title { flex: 1; min-width: 0; font-size: 14px; font-weight: 500; color: var(--text);
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
#preview-dl-btn { width: 36px; height: 36px; border-radius: 50%; border: none; cursor: pointer;
  background: rgba(255,255,255,0.1); color: var(--text); display: flex; align-items: center;
  justify-content: center; flex-shrink: 0; transition: background .15s; }
#preview-dl-btn:hover { background: var(--accent); color: #fff; }
#preview-close-btn { width: 36px; height: 36px; border-radius: 50%; border: none; cursor: pointer;
  background: rgba(255,255,255,0.08); color: var(--text2); display: flex; align-items: center;
  justify-content: center; flex-shrink: 0; transition: background .15s, color .15s; }
#preview-close-btn:hover { background: rgba(239,68,68,.25); color: #ef4444; }
#preview-body { flex: 1; overflow: auto; display: flex; align-items: center;
  justify-content: center; padding: 0; position: relative; background: #000; }
#preview-body iframe { width: 100%; height: 100%; border: none; background: #fff; }
#preview-body video, #preview-body audio { max-width: 100%; max-height: 100%; }
#preview-body img { max-width: 100%; max-height: 100%; object-fit: contain; }
#preview-spinner { position: absolute; inset: 0; display: flex; align-items: center;
  justify-content: center; background: #000; z-index: 5; }
#preview-spinner svg { animation: spin 1s linear infinite; color: var(--accent); }
@keyframes spin { to { transform: rotate(360deg); } }
#preview-unsupported { display: flex; flex-direction: column; align-items: center;
  justify-content: center; text-align: center; padding: 48px 32px; gap: 0; min-height: 320px; }
.pu-icon-wrap { width: 96px; height: 96px; border-radius: 50%; background: rgba(255,255,255,0.05);
  border: 1px solid rgba(255,255,255,0.1); display: flex; align-items: center;
  justify-content: center; margin-bottom: 24px; opacity: .75; }
#preview-unsupported h3 { font-size: 20px; font-weight: 700; color: var(--text); margin-bottom: 10px; }
#preview-unsupported p { font-size: 14px; color: var(--text3); margin-bottom: 28px; max-width: 340px; line-height: 1.6; }
.pu-dl-btn { display: inline-flex; align-items: center; gap: 10px; padding: 13px 28px;
  border-radius: 50px; border: none; cursor: pointer; background: var(--accent); color: #fff;
  font-size: 15px; font-weight: 600; font-family: var(--sans); transition: all .2s;
  box-shadow: 0 4px 20px rgba(4,131,195,.4); }
.pu-dl-btn:hover { filter: brightness(1.12); transform: translateY(-1px); }

/* Search results */
.sri { display: flex; align-items: center; gap: 14px; padding: 10px 12px;
  cursor: pointer; border-bottom: 0.9px solid rgba(44,44,44,.6); transition: background .08s; }
.sri:last-child { border-bottom: none; }
.sri:active { background: var(--surface2); }
.sri-icon { flex-shrink: 0; display: flex; align-items: center; justify-content: center; width: 46px; height: 46px; }
.sri-info { flex: 1; min-width: 0; overflow: hidden; }
.sri-name { font-size: 15px; font-weight: 400; color: var(--text); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.sri-meta { display: flex; justify-content: space-between; align-items: center; margin-top: 3px; }
.sri-size { font-size: 12px; color: var(--text3); }
.sri-date { font-size: 12px; color: var(--text3); margin-left: auto; padding-left: 8px; white-space: nowrap; }

/* Folder action panel */
.fa-panel { background: var(--surface2); border-radius: var(--r8); padding: 14px;
  margin-top: 8px; border: 1px solid var(--border); }
.fa-panel-title { font-size: 12px; font-weight: 700; color: var(--text3);
  text-transform: uppercase; letter-spacing: .05em; margin-bottom: 10px; }
.fa-input-row { display: flex; gap: 8px; }
.fa-input-row input { flex: 1; font-size: 13px; padding: 8px 12px; height: 36px; }
.fa-input-row button { height: 36px; padding: 0 14px; flex-shrink: 0; font-size: 13px; }

/* Login */
.lp { min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
.lcard { background: var(--header); border: 1px solid var(--border2); border-radius: var(--r16);
  padding: 40px 32px; width: 100%; max-width: 380px; box-shadow: var(--shadow); }
.llogo { text-align: center; margin-bottom: 32px; }
.llogo h1 { font-size: 26px; font-weight: 800; }
.llogo h1 span { color: var(--accent); }
.llogo p { color: var(--text2); font-size: 14px; margin-top: 6px; }
.lerr { background: rgba(239,68,68,.1); border: 1px solid rgba(239,68,68,.3); border-radius: var(--r8);
  padding: 12px 14px; color: var(--red); font-size: 14px; margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }
.lhint { font-size: 12px; color: var(--text3); text-align: center; margin-top: 20px; line-height: 1.6; }

@media (max-width: 640px) {
  .sidebar { display: none; }
  nav { padding: 0 10px; gap: 6px; }
  .nav-search-wrap { max-width: 100%; }
  .toolbar { padding: 8px 12px; }
  .fab-main { width: 54px; height: 54px; }
  #selbar { padding: 8px 10px; gap: 2px; }
  .sel-btn span { display: none; }
}
"""

_JS = """
function toast(msg,type=''){
  const t=document.getElementById('toast');
  t.textContent=msg;t.className='show '+type;
  clearTimeout(t._t);t._t=setTimeout(()=>t.className='',3500);
}
function bar(on){
  const b=document.getElementById('bar');
  b.className=on?'on':'done';
  if(!on)setTimeout(()=>b.className='',800);
}
function openModal(id){document.getElementById('m-'+id).classList.add('open');}
function closeModal(id){document.getElementById('m-'+id).classList.remove('open');}
document.addEventListener('DOMContentLoaded',()=>{
  document.querySelectorAll('.moverlay').forEach(el=>
    el.addEventListener('click',e=>{if(e.target===el)el.classList.remove('open');})
  );
  if(typeof initPage==='function')initPage();
});
"""

def _page(body: str, title: str = "SecureBox") -> web.Response:
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<title>{title} — SecureBox</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Google+Sans:wght@400;500;700&family=Roboto:wght@400;500;700&display=swap" rel="stylesheet">
<style>{_CSS}</style>
</head><body>
<div id="bar"></div>
<div id="toast"></div>
{body}
<script>{_JS}</script>
</body></html>"""
    return web.Response(text=html, content_type="text/html")


# ─── Handlers ──────────────────────────────────────────────────────────────────

async def handle_login(request: web.Request) -> web.Response:
    import os
    tok = request.cookies.get("session")
    if tok and _verify(tok):
        raise web.HTTPFound("/files")

    error = ""
    if request.method == "POST":
        data = await request.post()
        pw = data.get("password", "")
        stored_hash = os.getenv("WEBUI_PASSWORD_HASH", "")
        stored_plain = os.getenv("WEBUI_PASSWORD", "")

        if stored_hash:
            ok = _hash_pw(pw) == stored_hash
        elif stored_plain:
            ok = pw == stored_plain
        else:
            ok = True  # no password set — open access

        if ok:
            # Get first user id from DB
            files_col = request.app["files_col"]
            first_file = await files_col.find_one({})
            uid = first_file["user_id"] if first_file else 0
            resp = web.HTTPFound("/files")
            resp.set_cookie("session", _make_token(uid), max_age=86400*7, httponly=True, samesite="Lax")
            raise resp
        else:
            error = "Incorrect password."

    err_html = f'<div class="lerr">{_icon("alert",16)} {error}</div>' if error else ""
    return _page(f"""
<div class="lp">
  <div class="lcard">
    <div class="llogo">
      <div style="font-size:48px;margin-bottom:8px">🔒</div>
      <h1>Secure<span>Box</span></h1>
      <p>Sign in to manage your files</p>
    </div>
    {err_html}
    <form method="POST" onsubmit="return true">
      <div class="fg">
        <label>Password</label>
        <input name="password" type="password" placeholder="Enter your password" autofocus autocomplete="current-password">
      </div>
      <button type="submit" class="btn btn-primary btn-wide" style="height:46px;margin-top:8px;font-size:16px">
        {_icon("login_arrow",18)} Sign In
      </button>
    </form>
    <p class="lhint">Set password via .env file:<br><code>WEBUI_PASSWORD=yourpassword</code></p>
  </div>
</div>""", "Sign In")


async def handle_logout(request: web.Request) -> web.Response:
    resp = web.HTTPFound("/")
    resp.del_cookie("session")
    raise resp


@require_auth
async def handle_files(request: web.Request) -> web.Response:
    uid = request["uid"]
    files_col = request.app["files_col"]
    folders_col = request.app["folders_col"]

    # Get sidebar folders
    folders_cursor = folders_col.find({"user_id": uid}).sort("created_at", -1)
    sidebar_folders = [doc["folder"] for doc in await folders_cursor.to_list(length=100)]

    folders_html = ""
    if sidebar_folders:
        for f in sidebar_folders:
            fe = f.replace("'", "&#39;").replace('"', "&quot;")
            folders_html += f'<div class="sb-folder" onclick="filterByFolder(\'{fe}\')" data-folder="{fe}">{_icon("folder",14)} <span class="sb-folder-name">{f}</span></div>'

    skel = "".join(f"""<div class="file-item">
      <div class="fi-cb"><div class="custom-cb"></div></div>
      <div class="sk sk-i"></div>
      <div class="fi-info">
        <div class="sk sk-n" style="margin-bottom:6px"></div>
        <div class="sk sk-s"></div>
      </div>
    </div>""" for _ in range(8))

    return _page(f"""
<nav>
  <div class="nav-logo">
    <span style="font-size:22px">🔒</span>
    <span class="nav-logo-text">Secure<span>Box</span></span>
  </div>
  <div class="nav-center">
    <div class="nav-search-wrap">
      {_icon("search",16)}
      <input id="nav-search-input" type="text" placeholder="Search files and folders…"
        onkeydown="if(event.key==='Enter')doNavSearch()"
        oninput="onNavInput(this.value)">
    </div>
  </div>
  <a href="/logout" class="btn btn-ghost btn-sm">{_icon("signout",16)} Sign out</a>
</nav>

<div class="layout">
  <aside class="sidebar">
    <div class="sb-item active" id="sb-all" onclick="showAll()">
      {_icon("home",18)} All Files
    </div>
    <div class="sb-item" onclick="openSearchModal()">
      {_icon("search",18)} Search
    </div>
    <div class="sb-divider"></div>
    <div class="sb-label">Folders</div>
    {folders_html}
    <div class="sb-divider"></div>
    <a href="/logout" class="sb-item" style="color:var(--red)">
      {_icon("signout",18)} Sign out
    </a>
  </aside>

  <div class="main">
    <div class="toolbar">
      <div class="breadcrumb" id="bc">
        <span class="bc-crumb last" id="bc-label">All Files</span>
      </div>
      <button class="btn btn-icon" onclick="load()" title="Refresh">{_icon("refresh",18)}</button>
    </div>
    <div style="padding:8px 12px;overflow-x:auto">
      <div class="filter-chips" id="filter-chips">
        <div class="chip active" data-ft="all" onclick="setType('all')">All</div>
        <div class="chip" data-ft="document" onclick="setType('document')">{_icon("file",12)} Documents</div>
        <div class="chip" data-ft="video" onclick="setType('video')">{_icon("video",12)} Videos</div>
        <div class="chip" data-ft="photo" onclick="setType('photo')">{_icon("image",12)} Photos</div>
        <div class="chip" data-ft="audio" onclick="setType('audio')">{_icon("audio",12)} Audio</div>
      </div>
    </div>
    <div class="file-area" id="file-area">
      <div id="fl">{skel}</div>
    </div>
  </div>
</div>

<!-- FAB -->
<div id="fab">
  <div id="fab-opts" class="fab-options" style="display:none"></div>
  <button class="fab-main" id="fab-btn" onclick="toggleFab()" title="Actions">
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
  <button class="sel-btn" onclick="selFolder()" title="Move to Folder">{_icon("folder",20)}<span>Folder</span></button>
  <button class="sel-btn danger" onclick="selDel()" title="Delete">{_icon("delete",20)}<span>Delete</span></button>
</div>

<!-- Rename modal -->
<div class="moverlay" id="m-rename"><div class="modal">
  <div class="modal-title">{_icon("rename",18)} Rename File</div>
  <div class="fg"><label>New name</label><input id="i-rename" type="text"></div>
  <div class="macts">
    <button class="btn btn-ghost btn-sm" onclick="closeModal('rename')">Cancel</button>
    <button class="btn btn-primary btn-sm" onclick="doRename()">Rename</button>
  </div>
</div></div>

<!-- Delete modal -->
<div class="moverlay" id="m-delete"><div class="modal">
  <div class="modal-title">{_icon("delete",18)} Delete File</div>
  <p id="del-msg" style="color:var(--text2);font-size:14px;margin-bottom:6px"></p>
  <p style="font-size:12px;color:var(--text3)">This cannot be undone.</p>
  <div class="macts">
    <button class="btn btn-ghost btn-sm" onclick="closeModal('delete')">Cancel</button>
    <button class="btn btn-danger btn-sm" onclick="doDelete()">Delete</button>
  </div>
</div></div>

<!-- Move to Folder modal -->
<div class="moverlay" id="m-folder"><div class="modal">
  <div class="modal-title">{_icon("folder",18)} Move to Folder</div>
  <div class="fg">
    <label>Folder name (comma-separated for multiple)</label>
    <input id="i-folder" type="text" placeholder="e.g. Work, Personal">
  </div>
  <div class="fg" id="existing-folders-wrap" style="display:none">
    <label>Or pick existing</label>
    <div id="existing-folders" style="display:flex;flex-wrap:wrap;gap:6px;margin-top:4px"></div>
  </div>
  <div class="macts">
    <button class="btn btn-ghost btn-sm" onclick="closeModal('folder')">Cancel</button>
    <button class="btn btn-primary btn-sm" onclick="doMoveToFolder()">Apply</button>
  </div>
</div></div>

<!-- Search modal -->
<div class="moverlay" id="m-search"><div class="modal" style="max-width:480px">
  <div class="modal-title">{_icon("search",18)} Search Files</div>
  <div class="fg" style="display:flex;gap:8px;margin-bottom:0">
    <input id="i-search" type="text" placeholder="Search by name or folder…" style="flex:1">
    <button class="btn btn-primary" onclick="doSearch()" style="flex-shrink:0">{_icon("search",16)}</button>
  </div>
  <div id="search-res" style="max-height:340px;overflow-y:auto;margin-top:12px;border:1px solid var(--border);border-radius:var(--r8)"></div>
  <div class="macts"><button class="btn btn-ghost btn-sm" onclick="closeModal('search')">Close</button></div>
</div></div>

<!-- Preview overlay -->
<div id="preview-overlay">
  <div id="preview-bar">
    <button id="preview-close-btn" onclick="closePreview()" title="Close">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
    </button>
    <span id="preview-title"></span>
    <button id="preview-dl-btn" onclick="previewDownload()" title="Download in Telegram">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M8 17l4 4 4-4m0 0V3M4 20h16"/></svg>
    </button>
  </div>
  <div id="preview-body">
    <div id="preview-spinner" style="display:none">
      <svg width="42" height="42" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg>
    </div>
  </div>
</div>

<script>
const IC = {{
  file: '{_icon("file",32,"","#607d8b").replace("'","&#39;")}',
  image: '{_icon("image",32,"","#a78bfa").replace("'","&#39;")}',
  video: '{_icon("video",32,"","#f87171").replace("'","&#39;")}',
  audio: '{_icon("audio",32,"","#e55835").replace("'","&#39;")}',
  folder: '{_icon("folder",32,"","#0483c3").replace("'","&#39;")}',
  dl: '{_icon("download",20).replace("'","&#39;")}'
}};

function getIco(ft) {{
  if(ft==='photo') return IC.image;
  if(ft==='video'||ft==='video_note') return IC.video;
  if(ft==='audio'||ft==='voice') return IC.audio;
  return IC.file;
}}

let files=[], sel=new Set();
let renameId=null, delIds=[], folderIds=[];
let activeType='all', activeFolder=null, fabOpen=false;
let longPressTimer=null, _pvId=null;

function sz(b){{if(!b||isNaN(b))return'—';b=+b;if(b<1024)return b+' B';if(b<1048576)return(b/1024).toFixed(1)+' KB';if(b<1073741824)return(b/1048576).toFixed(1)+' MB';return(b/1073741824).toFixed(2)+' GB'}}
function dt(s){{if(!s)return'—';const d=new Date(s),now=new Date(),diff=now-d;if(diff<86400000)return d.toLocaleTimeString([],{{hour:'2-digit',minute:'2-digit'}});if(diff<604800000)return d.toLocaleDateString([],{{weekday:'short',month:'short',day:'numeric'}});return d.toLocaleDateString([],{{year:'numeric',month:'short',day:'numeric'}})}}

function initPage() {{ load(); }}

function showAll() {{
  activeFolder=null;
  document.querySelectorAll('.sb-folder').forEach(e=>e.classList.remove('active'));
  document.getElementById('sb-all').classList.add('active');
  document.getElementById('bc-label').textContent='All Files';
  load();
}}

function filterByFolder(f) {{
  activeFolder=f;
  document.querySelectorAll('.sb-folder').forEach(e=>e.classList.toggle('active',e.dataset.folder===f));
  document.getElementById('sb-all').classList.remove('active');
  document.getElementById('bc-label').textContent='📁 '+f;
  load();
}}

function setType(t) {{
  activeType=t;
  document.querySelectorAll('.chip').forEach(c=>c.classList.toggle('active',c.dataset.ft===t));
  load();
}}

async function load() {{
  sel.clear(); clearSel(); closeFab();
  const fl=document.getElementById('fl');
  fl.innerHTML=Array(6).fill(`<div class="file-item">
    <div class="fi-cb"><div class="custom-cb"></div></div>
    <div class="sk sk-i"></div>
    <div class="fi-info">
      <div class="sk sk-n" style="margin-bottom:6px"></div>
      <div class="sk sk-s"></div>
    </div></div>`).join('');
  bar(true);
  try {{
    let url='/api/files';
    const params=[];
    if(activeType&&activeType!=='all') params.push('type='+encodeURIComponent(activeType));
    if(activeFolder) params.push('folder='+encodeURIComponent(activeFolder));
    if(params.length) url+='?'+params.join('&');
    const r=await fetch(url);
    if(!r.ok) throw new Error('HTTP '+r.status);
    const d=await r.json();
    files=d.files||[];
    render();
  }}catch(e){{
    fl.innerHTML=`<div class="empty"><h3>Failed to load</h3><p>${{e.message}}</p></div>`;
  }}
  bar(false);
}}

function _fileItemHTML(f) {{
  const nm=f.file_name.replace(/"/g,'&quot;').replace(/'/g,'&#39;');
  const selCls=sel.has(f._id)?' sel':'';
  const chkCls=sel.has(f._id)?'custom-cb checked':'custom-cb';
  const foldersStr=f.folders&&f.folders.length?f.folders.map(x=>'📁 '+x).join(' · '):'';
  return `<div class="file-item${{selCls}}" data-id="${{f._id}}" data-name="${{nm}}" data-type="${{f.file_type}}"
      onclick="itemClick(event,'${{f._id}}')"
      oncontextmenu="event.preventDefault();longPress('${{f._id}}')"
      ontouchstart="startLong(event,'${{f._id}}')" ontouchend="endLong()" ontouchmove="endLong()">
    <div class="fi-cb" onclick="event.stopPropagation();toggleSelCustom('${{f._id}}',this.querySelector('.custom-cb'))">
      <div class="${{chkCls}}"></div>
    </div>
    <div class="fi-icon">${{getIco(f.file_type)}}</div>
    <div class="fi-info">
      <div class="fi-name">${{f.file_name}}</div>
      ${{foldersStr?`<div class="fi-folders">${{foldersStr}}</div>`:''}}<div class="fi-meta">
        <span class="fi-size">${{sz(f.file_size)}} · ${{f.file_type}}</span>
        <span class="fi-date">${{dt(f.message_date)}}</span>
      </div>
    </div>
    <button class="btn-icon fi-act" title="Send via Telegram" onclick="event.stopPropagation();sendViaBot('${{f._id}}')">
      ${{IC.dl}}
    </button>
  </div>`;
}}

function render() {{
  const fl=document.getElementById('fl');
  if(!files.length) {{
    fl.innerHTML=`<div class="empty"><div class="empty-icon">${{IC.file}}</div><h3>No files found</h3><p>Send files to your Telegram bot to store them here</p></div>`;
    return;
  }}
  fl.innerHTML=files.map(f=>_fileItemHTML(f)).join('');
}}

function itemClick(e,id) {{
  if(e.target.classList.contains('custom-cb'))return;
  if(document.body.classList.contains('select-mode')) {{
    const cb=e.currentTarget.querySelector('.custom-cb');
    if(cb)toggleSelCustom(id,cb);
    return;
  }}
  const f=files.find(x=>x._id===id);
  if(f) openPreview(id, f.file_type, f.file_name);
}}

function startLong(e,id){{longPressTimer=setTimeout(()=>longPress(id),500);}}
function endLong(){{clearTimeout(longPressTimer);}}
function longPress(id){{
  if(!document.body.classList.contains('select-mode')) document.body.classList.add('select-mode');
  const row=document.querySelector(`[data-id="${{id}}"]`);
  const cb=row?.querySelector('.custom-cb');
  if(cb&&!cb.classList.contains('checked'))toggleSelCustom(id,cb);
}}

function toggleSelCustom(id,cb){{
  const isChecked=cb.classList.contains('checked');
  if(isChecked){{cb.classList.remove('checked');sel.delete(id);}}
  else{{cb.classList.add('checked');sel.add(id);}}
  const r=document.querySelector(`.file-item[data-id="${{id}}"]`);
  if(r)r.classList.toggle('sel',!isChecked);
  if(!document.body.classList.contains('select-mode')) document.body.classList.add('select-mode');
  updateSel();
}}

function updateSel(){{
  document.getElementById('selcnt').textContent=sel.size+' selected';
  document.getElementById('selbar').classList.toggle('show',sel.size>0);
  if(sel.size===0) document.body.classList.remove('select-mode');
}}

function clearSel(){{
  sel.clear();
  document.querySelectorAll('.file-item .custom-cb').forEach(c=>c.classList.remove('checked'));
  document.querySelectorAll('.file-item.sel').forEach(r=>r.classList.remove('sel'));
  document.body.classList.remove('select-mode');
  document.getElementById('selbar').classList.remove('show');
  updateSel();
}}

async function openPreview(id,ft,name){{
  _pvId=id;
  const ov=document.getElementById('preview-overlay');
  document.getElementById('preview-title').textContent=name||'Preview';
  const body=document.getElementById('preview-body');
  const spinner=document.getElementById('preview-spinner');
  [...body.children].forEach(c=>{{if(c!==spinner)c.remove();}});
  spinner.style.display='flex';
  ov.classList.add('open');
  try{{
    const src=`/api/preview/${{id}}`;
    if(ft==='photo'){{
      const img=document.createElement('img');
      img.onload=()=>{{spinner.style.display='none';}};
      img.onerror=()=>{{spinner.style.display='none';showUnsupported(name);}};
      img.src=src;
      body.appendChild(img);
    }} else if(ft==='video'||ft==='video_note'){{
      const vid=document.createElement('video');
      vid.controls=true;vid.autoplay=true;vid.style.maxWidth='100%';vid.style.maxHeight='100%';
      vid.oncanplay=()=>spinner.style.display='none';
      vid.onerror=()=>{{spinner.style.display='none';showUnsupported(name);}};
      vid.src=src;
      body.appendChild(vid);
    }} else if(ft==='audio'||ft==='voice'){{
      spinner.style.display='none';
      const wrap=document.createElement('div');
      wrap.style.cssText='display:flex;flex-direction:column;align-items:center;gap:20px;padding:40px 24px;';
      wrap.innerHTML=`<div style="font-size:80px">🎵</div>
        <div style="font-size:16px;font-weight:600;color:var(--text);text-align:center;max-width:280px">${{name}}</div>
        <audio controls autoplay style="width:100%;max-width:340px"><source src="${{src}}"></audio>`;
      body.appendChild(wrap);
    }} else {{
      spinner.style.display='none';
      showUnsupported(name);
    }}
  }}catch(e){{
    spinner.style.display='none';showUnsupported(name);
  }}
}}

function showUnsupported(name){{
  const body=document.getElementById('preview-body');
  const d=document.createElement('div');d.id='preview-unsupported';
  d.innerHTML=`<div class="pu-icon-wrap">${{IC.file}}</div>
    <h3>Can't preview this file</h3>
    <p>This file type doesn't support in-browser preview.<br>Use Telegram to access it.</p>
    <p style="font-size:13px;color:var(--text3);margin-top:8px">${{name}}</p>`;
  body.appendChild(d);
}}

function closePreview(){{
  const ov=document.getElementById('preview-overlay');
  ov.classList.remove('open');
  const body=document.getElementById('preview-body');
  const spinner=document.getElementById('preview-spinner');
  [...body.children].forEach(c=>{{if(c!==spinner)c.remove();}});
  const vid=body.querySelector('video');if(vid){{vid.pause();vid.src='';}}
  const aud=body.querySelector('audio');if(aud){{aud.pause();aud.src='';}}
  spinner.style.display='none';
  _pvId=null;
}}

function previewDownload(){{if(_pvId)sendViaBot(_pvId);}}

function sendViaBot(id){{
  const f=files.find(x=>x._id===id);
  toast('Send the file via @bot — use /start and the inline explore button','warn');
}}

function selDl(){{toast('Use Telegram bot to download files. Inline search: @YourBot file name','warn');}}
function selRename(){{
  if(sel.size===1){{
    const id=[...sel][0];
    const row=document.querySelector(`[data-id="${{id}}"]`);
    openRename(id,row?.dataset.name||'');
  }} else toast('Select one file to rename','warn');
}}
function selFolder(){{
  if(sel.size){{
    folderIds=[...sel];
    document.getElementById('i-folder').value='';
    loadExistingFolders();
    openModal('folder');
  }}
}}
function selDel(){{
  if(sel.size){{
    delIds=[...sel];
    const name=document.querySelector(`[data-id="${{[...sel][0]}}"]`)?.dataset.name||'';
    document.getElementById('del-msg').textContent=sel.size===1?`Delete "${{name}}"?`:`Delete ${{sel.size}} files?`;
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
  bar(false);r.ok?toast('Renamed','ok'):toast('Failed to rename','err');load();
}}

async function doDelete(){{
  closeModal('delete');bar(true);
  await Promise.all(delIds.map(id=>fetch(`/api/delete/${{id}}`,{{method:'POST'}})));
  bar(false);toast('Deleted','ok');clearSel();load();
}}

async function loadExistingFolders(){{
  try{{
    const r=await fetch('/api/folders');
    const d=await r.json();
    const wrap=document.getElementById('existing-folders-wrap');
    const cont=document.getElementById('existing-folders');
    if(d.folders&&d.folders.length){{
      wrap.style.display='';
      cont.innerHTML=d.folders.map(f=>`<span class="chip" onclick="document.getElementById('i-folder').value=(document.getElementById('i-folder').value?document.getElementById('i-folder').value+', ':'')+this.textContent.trim();this.classList.add('active')">${{f}}</span>`).join('');
    }}
  }}catch(e){{}}
}}

async function doMoveToFolder(){{
  const raw=document.getElementById('i-folder').value.trim();
  const folders=raw?raw.split(',').map(s=>s.trim()).filter(Boolean):[];
  closeModal('folder');bar(true);
  await Promise.all(folderIds.map(id=>fetch(`/api/set_folders/${{id}}`,{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{folders}})}})));
  bar(false);toast('Folders updated','ok');clearSel();load();
}}

async function doNavSearch(){{
  const q=document.getElementById('nav-search-input').value.trim();if(!q)return;
  document.getElementById('i-search').value=q;
  document.getElementById('search-res').innerHTML='';
  openModal('search');doSearch();
}}
function onNavInput(v){{}}

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
    el.innerHTML=`<div style="padding:20px;text-align:center;color:var(--text3);font-size:14px">No results for "${{q}}"</div>`;
    return;
  }}
  el.innerHTML=d.files.map(f=>`<div class="sri" onclick="closeModal('search');openPreview('${{f._id}}','${{f.file_type}}','${{f.file_name.replace(/'/g,"&#39;")}}')">
    <div class="sri-icon">${{getIco(f.file_type)}}</div>
    <div class="sri-info">
      <div class="sri-name">${{f.file_name}}</div>
      <div class="sri-meta">
        <span class="sri-size">${{sz(f.file_size)}} · ${{f.file_type}}</span>
        <span class="sri-date">${{dt(f.message_date)}}</span>
      </div>
    </div>
  </div>`).join('');
}}

function toggleFab(){{
  fabOpen=!fabOpen;
  const btn=document.getElementById('fab-btn');
  const opts=document.getElementById('fab-opts');
  if(fabOpen){{
    btn.classList.add('open');
    opts.style.display='flex';
    opts.innerHTML=`
      <div class="fab-opt" onclick="closeFab();openSearchModal()">
        ${{IC.file}} <span>Search Files</span>
      </div>`;
  }}else{{closeFab();}}
}}
function closeFab(){{
  fabOpen=false;
  document.getElementById('fab-btn').classList.remove('open');
  document.getElementById('fab-opts').style.display='none';
}}
document.addEventListener('click',e=>{{
  if(fabOpen&&!document.getElementById('fab').contains(e.target))closeFab();
}});

document.addEventListener('keydown',e=>{{
  if(e.key==='Escape'){{
    const ov=document.getElementById('preview-overlay');
    if(ov&&ov.classList.contains('open')){{closePreview();return;}}
    document.querySelectorAll('.moverlay.open').forEach(m=>m.classList.remove('open'));
    clearSel();closeFab();
  }}
  if(e.key==='Enter'){{
    if(document.getElementById('m-rename').classList.contains('open'))doRename();
    else if(document.getElementById('m-search').classList.contains('open'))doSearch();
  }}
}});
</script>""", "Files")


# ─── API routes ────────────────────────────────────────────────────────────────

@require_auth
async def api_files(request: web.Request) -> web.Response:
    uid = request["uid"]
    files_col = request.app["files_col"]
    file_type = request.rel_url.query.get("type")
    folder = request.rel_url.query.get("folder")

    query = {"user_id": uid}
    if file_type and file_type != "all":
        query["file_type"] = file_type
    if folder:
        query["folders"] = folder

    cursor = files_col.find(query).sort("message_date", -1).limit(200)
    raw = await cursor.to_list(length=200)

    def serialize(f):
        f["_id"] = str(f["_id"])
        if "message_date" in f and hasattr(f["message_date"], "isoformat"):
            f["message_date"] = f["message_date"].isoformat()
        # Migrate old "tags" field to "folders" if needed
        if "tags" in f and "folders" not in f:
            f["folders"] = f.pop("tags")
        elif "folders" not in f:
            f["folders"] = []
        return f

    return web.json_response({"files": [serialize(f) for f in raw]})


@require_auth
async def api_folders(request: web.Request) -> web.Response:
    uid = request["uid"]
    folders_col = request.app["folders_col"]
    cursor = folders_col.find({"user_id": uid}).sort("created_at", -1)
    docs = await cursor.to_list(length=200)
    return web.json_response({"folders": [d["folder"] for d in docs]})


@require_auth
async def api_rename(request: web.Request) -> web.Response:
    uid = request["uid"]
    file_id = request.match_info["fid"]
    files_col = request.app["files_col"]
    body = await request.json()
    name = body.get("name", "").strip()
    if not name:
        raise web.HTTPBadRequest(reason="Name required")
    try:
        await files_col.update_one(
            {"_id": ObjectId(file_id), "user_id": uid},
            {"$set": {"file_name": name}}
        )
        return web.json_response({"ok": True})
    except Exception as e:
        raise web.HTTPInternalServerError(reason=str(e))


@require_auth
async def api_delete(request: web.Request) -> web.Response:
    uid = request["uid"]
    file_id = request.match_info["fid"]
    files_col = request.app["files_col"]
    try:
        await files_col.delete_one({"_id": ObjectId(file_id), "user_id": uid})
        return web.json_response({"ok": True})
    except Exception as e:
        raise web.HTTPInternalServerError(reason=str(e))


@require_auth
async def api_set_folders(request: web.Request) -> web.Response:
    uid = request["uid"]
    file_id = request.match_info["fid"]
    files_col = request.app["files_col"]
    folders_col = request.app["folders_col"]
    body = await request.json()
    folders = body.get("folders", [])
    try:
        await files_col.update_one(
            {"_id": ObjectId(file_id), "user_id": uid},
            {"$set": {"folders": folders}}
        )
        for folder in folders:
            await folders_col.update_one(
                {"user_id": uid, "folder": folder},
                {"$setOnInsert": {"created_at": datetime.utcnow()}},
                upsert=True
            )
        return web.json_response({"ok": True})
    except Exception as e:
        raise web.HTTPInternalServerError(reason=str(e))


@require_auth
async def api_search(request: web.Request) -> web.Response:
    uid = request["uid"]
    q = request.rel_url.query.get("q", "").strip()
    if not q:
        return web.json_response({"files": []})
    files_col = request.app["files_col"]
    # Search by file name (regex) or folder name
    cursor = files_col.find({
        "user_id": uid,
        "$or": [
            {"file_name": {"$regex": q, "$options": "i"}},
            {"folders": {"$regex": q, "$options": "i"}},
            # Also search old "tags" field for backward compat
            {"tags": {"$regex": q, "$options": "i"}},
        ]
    }).sort("message_date", -1).limit(50)
    raw = await cursor.to_list(length=50)

    def serialize(f):
        f["_id"] = str(f["_id"])
        if "message_date" in f and hasattr(f["message_date"], "isoformat"):
            f["message_date"] = f["message_date"].isoformat()
        if "tags" in f and "folders" not in f:
            f["folders"] = f.pop("tags")
        elif "folders" not in f:
            f["folders"] = []
        return f

    return web.json_response({"files": [serialize(f) for f in raw]})


@require_auth
async def api_preview(request: web.Request) -> web.Response:
    """
    Stream a file from the Telegram bot for in-browser preview.
    For images/video/audio, we download from Telegram servers and proxy the bytes.
    """
    import aiohttp as _aiohttp
    uid = request["uid"]
    file_id_str = request.match_info["fid"]
    files_col = request.app["files_col"]
    bot_instance = request.app.get("bot_instance")

    try:
        file_doc = await files_col.find_one({"_id": ObjectId(file_id_str), "user_id": uid})
        if not file_doc:
            raise web.HTTPNotFound(reason="File not found")

        tg_file_id = file_doc.get("file_id")
        file_type = file_doc.get("file_type", "document")
        file_name = file_doc.get("file_name", "file")

        mime_map = {
            "photo": "image/jpeg",
            "video": "video/mp4",
            "video_note": "video/mp4",
            "audio": "audio/mpeg",
            "voice": "audio/ogg",
            "document": "application/octet-stream",
        }
        content_type = mime_map.get(file_type, "application/octet-stream")
        # Try to guess from file extension
        ext = file_name.rsplit(".", 1)[-1].lower() if "." in file_name else ""
        ext_map = {
            "jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png",
            "gif": "image/gif", "webp": "image/webp",
            "mp4": "video/mp4", "mov": "video/quicktime",
            "mp3": "audio/mpeg", "ogg": "audio/ogg", "m4a": "audio/mp4",
            "pdf": "application/pdf",
        }
        if ext in ext_map:
            content_type = ext_map[ext]

        if not bot_instance:
            raise web.HTTPServiceUnavailable(reason="Bot not available")

        tg_file = await bot_instance.get_file(tg_file_id)
        file_path = tg_file.file_path

        # Construct telegram file download URL
        import os
        bot_token = os.getenv("BOT_TOKEN", "")
        dl_url = f"https://api.telegram.org/file/bot{bot_token}/{file_path}"

        range_hdr = request.headers.get("Range")
        req_headers = {}
        if range_hdr:
            req_headers["Range"] = range_hdr

        async with _aiohttp.ClientSession() as session:
            async with session.get(dl_url, headers=req_headers) as tg_resp:
                status = tg_resp.status
                resp_headers = {
                    "Content-Type": tg_resp.headers.get("Content-Type", content_type),
                    "Content-Disposition": f'inline; filename="{file_name}"',
                    "Accept-Ranges": "bytes",
                }
                for h in ("Content-Length", "Content-Range"):
                    if h in tg_resp.headers:
                        resp_headers[h] = tg_resp.headers[h]

                response = web.StreamResponse(status=status, headers=resp_headers)
                await response.prepare(request)
                async for chunk in tg_resp.content.iter_chunked(65536):
                    await response.write(chunk)
                await response.write_eof()
                return response

    except web.HTTPException:
        raise
    except Exception as e:
        logger.error(f"api_preview error: {e}", exc_info=True)
        raise web.HTTPInternalServerError(reason=str(e))


# ─── App factory ───────────────────────────────────────────────────────────────

def create_app(files_collection, folders_collection, bot_instance=None) -> web.Application:
    app = web.Application(client_max_size=50 * 1024 * 1024)
    app["files_col"] = files_collection
    app["folders_col"] = folders_collection
    app["bot_instance"] = bot_instance

    app.router.add_route("GET",  "/",                  handle_login)
    app.router.add_route("POST", "/",                  handle_login)
    app.router.add_get("/logout",                      handle_logout)
    app.router.add_get("/files",                       handle_files)
    app.router.add_get("/api/files",                   api_files)
    app.router.add_get("/api/folders",                 api_folders)
    app.router.add_post("/api/rename/{fid}",           api_rename)
    app.router.add_post("/api/delete/{fid}",           api_delete)
    app.router.add_post("/api/set_folders/{fid}",      api_set_folders)
    app.router.add_get("/api/search",                  api_search)
    app.router.add_get("/api/preview/{fid}",           api_preview)

    return app
