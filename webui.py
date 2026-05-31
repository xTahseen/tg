import asyncio
import hashlib
import hmac
import json
import logging
import time
from functools import wraps

from aiohttp import web
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
import os

logger = logging.getLogger(__name__)

# ── Auth helpers ──────────────────────────────────────────────────────────────

WEBUI_SECRET = os.getenv("WEBUI_SECRET", "securebox-secret-change-me")
WEBUI_PASSWORD = os.getenv("WEBUI_PASSWORD", "")


def _sign(payload: dict) -> str:
    import base64
    data = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    sig = hmac.new(WEBUI_SECRET.encode(), data.encode(), hashlib.sha256).hexdigest()
    return f"{data}.{sig}"


def _verify(token: str) -> dict | None:
    try:
        import base64
        data, sig = token.rsplit(".", 1)
        expected = hmac.new(WEBUI_SECRET.encode(), data.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(base64.urlsafe_b64decode(data).decode())
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None


def _make_token(user_id: int) -> str:
    return _sign({"uid": user_id, "exp": time.time() + 86400 * 7})


def _hash_pw(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()


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


# ── Formatting helpers ────────────────────────────────────────────────────────

def _fmt_size(b: int) -> str:
    if not b:
        return "—"
    if b < 1024:
        return f"{b} B"
    if b < 1048576:
        return f"{b / 1024:.1f} KB"
    if b < 1073741824:
        return f"{b / 1048576:.1f} MB"
    return f"{b / 1073741824:.2f} GB"


def _icon(name: str, size: int = 20, cls: str = "", bg_color: str = None) -> str:
    cls_attr = f' class="{cls}"' if cls else ""
    icons = {
        "file":     '<path d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m2.25 0H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
        "image":    '<path d="M2.25 15.75l5.159-5.159a2.25 2.25 0 013.182 0l5.159 5.159m-1.5-1.5l1.409-1.409a2.25 2.25 0 013.182 0l2.909 2.909m-18 3.75h16.5a1.5 1.5 0 001.5-1.5V6a1.5 1.5 0 00-1.5-1.5H3.75A1.5 1.5 0 002.25 6v12a1.5 1.5 0 001.5 1.5zm10.5-11.25h.008v.008h-.008V8.25zm.375 0a.375.375 0 11-.75 0 .375.375 0 01.75 0z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
        "video":    '<path d="M15.75 10.5l4.72-4.72a.75.75 0 011.28.53v11.38a.75.75 0 01-1.28.53l-4.72-4.72M4.5 18.75h9a2.25 2.25 0 002.25-2.25v-9a2.25 2.25 0 00-2.25-2.25h-9A2.25 2.25 0 002.25 7.5v9a2.25 2.25 0 002.25 2.25z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
        "audio":    '<path d="M9 9l10.5-3m0 6.553v3.75a2.25 2.25 0 01-1.632 2.163l-1.32.377a1.803 1.803 0 11-.99-3.467l2.31-.66a2.25 2.25 0 001.632-2.163zm0 0V2.25L9 5.25v10.303m0 0v3.75a2.25 2.25 0 01-1.632 2.163l-1.32.377a1.803 1.803 0 01-.99-3.467l2.31-.66A2.25 2.25 0 009 15.553z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
        "document": '<path d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
        "tag":      '<path d="M9.568 3H5.25A2.25 2.25 0 003 5.25v4.318c0 .597.237 1.17.659 1.591l9.581 9.581c.699.699 1.78.872 2.607.33a18.095 18.095 0 005.223-5.223c.542-.827.369-1.908-.33-2.607L11.16 3.66A2.25 2.25 0 009.568 3z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M6 6h.008v.008H6V6z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
        "search":   '<path d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 15.803 7.5 7.5 0 0015.803 15.803z" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "home":     '<path d="M2.25 12l8.954-8.955a1.126 1.126 0 011.591 0L21.75 12M4.5 9.75v10.125c0 .621.504 1.125 1.125 1.125H9.75v-4.875c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125V21h4.125c.621 0 1.125-.504 1.125-1.125V9.75M8.25 21h8.25" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "rename":   '<path d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L6.832 19.82a4.5 4.5 0 01-1.897 1.13l-2.685.8.8-2.685a4.5 4.5 0 011.13-1.897L16.863 4.487zm0 0L19.5 7.125" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "delete":   '<path d="M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 01-2.244 2.077H8.084a2.25 2.25 0 01-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 00-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 013.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 00-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 00-7.5 0" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "signout":  '<path d="M15.75 9V5.25A2.25 2.25 0 0013.5 3h-6a2.25 2.25 0 00-2.25 2.25v13.5A2.25 2.25 0 007.5 21h6a2.25 2.25 0 002.25-2.25V15M12 9l-3 3m0 0l3 3m-3-3h12.75" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "back":     '<path d="M10.5 19.5L3 12m0 0l7.5-7.5M3 12h18" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "alert":    '<path d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "login":    '<path d="M15.75 9V5.25A2.25 2.25 0 0013.5 3h-6a2.25 2.25 0 00-2.25 2.25v13.5A2.25 2.25 0 007.5 21h6a2.25 2.25 0 002.25-2.25V15m3 0l3-3m0 0l-3-3m3 3H9" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "filter":   '<path d="M12 3c2.755 0 5.455.232 8.083.678.533.09.917.556.917 1.096v1.044a2.25 2.25 0 01-.659 1.591l-5.432 5.432a2.25 2.25 0 00-.659 1.591v2.927a2.25 2.25 0 01-1.244 2.013L9.75 21v-6.568a2.25 2.25 0 00-.659-1.591L3.659 7.409A2.25 2.25 0 013 5.818V4.774c0-.54.384-1.006.917-1.096A48.32 48.32 0 0112 3z" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "shield":   '<path d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "telegram": '<path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm4.64 6.8l-1.7 8c-.12.54-.48.67-.96.42l-2.67-1.97-1.29 1.24c-.14.14-.27.27-.55.27l.2-2.77 5.01-4.52c.22-.19-.05-.3-.34-.1L7.24 14.6l-2.61-.81c-.57-.18-.58-.57.12-.84l10.22-3.94c.47-.18.88.11.67.79z" fill="currentColor"/>',
        "sticker":  '<path d="M15.182 15.182a4.5 4.5 0 01-6.364 0M21 12a9 9 0 11-18 0 9 9 0 0118 0zM9.75 9.75c0 .414-.168.75-.375.75S9 10.164 9 9.75 9.168 9 9.375 9s.375.336.375.75zm-.375 0h.008v.015h-.008V9.75zm5.625 0c0 .414-.168.75-.375.75s-.375-.336-.375-.75.168-.75.375-.75.375.336.375.75zm-.375 0h.008v.015h-.008V9.75z" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "close":    '<path d="M6 18L18 6M6 6l12 12" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "check":    '<path d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "copy":     '<path d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
    }
    path = icons.get(name, icons["file"])
    svg = f'<svg{cls_attr} width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">{path}</svg>'
    if bg_color:
        return f'<div class="icon-bg" style="background-color:{bg_color}">{svg}</div>'
    return svg


def _file_icon(file_type: str, size: int = 22) -> str:
    mapping = {
        "photo":      ("image",    "#a78bfa"),
        "video":      ("video",    "#f87171"),
        "video_note": ("video",    "#fb923c"),
        "audio":      ("audio",    "#e55835"),
        "voice":      ("audio",    "#f59e0b"),
        "document":   ("document", "#60a5fa"),
        "sticker":    ("sticker",  "#34d399"),
    }
    name, color = mapping.get(file_type, ("file", "#607d8b"))
    return _icon(name, size, "", color)


# ── CSS ───────────────────────────────────────────────────────────────────────

_CSS = """
:root {
  --bg: #0d0d0d;
  --header: #161616;
  --surface: #1a1a1a;
  --surface2: #202020;
  --surface3: #282828;
  --border: #2a2a2a;
  --border2: #363636;
  --accent: #2563eb;
  --accent2: #1d4ed8;
  --accent-dim: rgba(37,99,235,.13);
  --green: #22c55e;
  --red: #ef4444;
  --yellow: #f59e0b;
  --text: #f0f0f0;
  --text2: #a0a0a0;
  --text3: #555;
  --r4: 4px; --r8: 8px; --r12: 12px; --r16: 16px;
  --sans: 'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif;
  --shadow: 0 8px 32px rgba(0,0,0,.7);
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { height: 100%; -webkit-text-size-adjust: 100%; }
body { background: var(--bg); color: var(--text); font-family: var(--sans); font-size: 15px; height: 100%; -webkit-font-smoothing: antialiased; overflow-x: hidden; }
a { color: var(--accent); text-decoration: none; }
::-webkit-scrollbar { width: 4px; height: 4px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 2px; }

/* Progress bar */
#bar { position: fixed; top: 0; left: 0; right: 0; height: 3px; background: var(--accent); transform: scaleX(0); transform-origin: left; transition: transform .4s; z-index: 9999; opacity: 0; }
#bar.on  { transform: scaleX(.7); opacity: 1; }
#bar.done { transform: scaleX(1); opacity: 0; transition: transform .3s, opacity .4s .2s; }

/* Toast */
#toast { position: fixed; bottom: 24px; left: 50%; transform: translateX(-50%) translateY(20px); background: var(--surface2); border: 1px solid var(--border2); color: var(--text); border-radius: 24px; padding: 12px 22px; font-size: 14px; z-index: 9999; opacity: 0; pointer-events: none; transition: all .22s ease; white-space: nowrap; box-shadow: var(--shadow); }
#toast.show { transform: translateX(-50%) translateY(0); opacity: 1; }
#toast.ok   { border-color: var(--green); color: var(--green); }
#toast.err  { border-color: var(--red);   color: var(--red); }
#toast.warn { border-color: var(--yellow); color: var(--yellow); }

/* Buttons */
.btn { display: inline-flex; align-items: center; gap: 8px; border: none; border-radius: var(--r8); cursor: pointer; font-size: 14px; font-weight: 500; font-family: var(--sans); transition: all .15s; white-space: nowrap; padding: 0 16px; height: 40px; }
.btn:active { transform: scale(.97); }
.btn-primary { background: var(--accent); color: #fff; }
.btn-primary:hover { background: var(--accent2); }
.btn-ghost { background: transparent; color: var(--text2); border: 1px solid var(--border2); }
.btn-ghost:hover { background: var(--surface3); color: var(--text); }
.btn-danger { background: rgba(239,68,68,.15); color: var(--red); border: 1px solid rgba(239,68,68,.3); }
.btn-danger:hover { background: rgba(239,68,68,.25); }
.btn-sm { height: 34px; padding: 0 13px; font-size: 13px; }
.btn-wide { width: 100%; justify-content: center; }

/* Inputs */
input, select, textarea { background: var(--surface3); color: var(--text); border: 1px solid var(--border); border-radius: var(--r8); padding: 11px 14px; font-size: 15px; font-family: var(--sans); width: 100%; outline: none; transition: border-color .15s, box-shadow .15s; }
input:focus, select:focus, textarea:focus { border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-dim); }
input::placeholder, textarea::placeholder { color: var(--text3); }
textarea { resize: vertical; min-height: 80px; }

/* Nav */
nav { background: var(--header); border-bottom: 1px solid var(--border); padding: 0 16px; display: flex; align-items: center; gap: 10px; height: 58px; position: sticky; top: 0; z-index: 200; }
.nav-logo { display: flex; align-items: center; gap: 10px; text-decoration: none; flex-shrink: 0; font-weight: 700; font-size: 17px; color: var(--text); }
.nav-logo svg { color: var(--accent); }
.nav-center { flex: 1; display: flex; justify-content: center; padding: 0 8px; }
.nav-search-wrap { display: flex; align-items: center; gap: 8px; background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.1); border-radius: 24px; padding: 0 14px; height: 38px; width: 100%; max-width: 400px; transition: background .18s, border-color .18s, box-shadow .18s; }
.nav-search-wrap:focus-within { background: rgba(255,255,255,0.1); border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-dim); }
.nav-search-wrap svg { color: var(--text3); flex-shrink: 0; }
#nav-search { background: transparent; border: none; outline: none; color: var(--text); font-size: 14px; width: 100%; padding: 0; box-shadow: none; }
#nav-search::placeholder { color: var(--text3); }

/* Layout */
.layout { display: flex; height: calc(100vh - 58px); overflow: hidden; }

/* Sidebar */
.sidebar { width: 220px; flex-shrink: 0; background: var(--header); border-right: 1px solid var(--border); padding: 12px 8px; display: flex; flex-direction: column; gap: 2px; overflow-y: auto; }
.sb-item { display: flex; align-items: center; gap: 10px; padding: 10px 12px; border-radius: var(--r8); cursor: pointer; font-size: 14px; font-weight: 500; color: var(--text2); transition: all .12s; border: 1px solid transparent; }
.sb-item:hover { background: var(--surface2); color: var(--text); }
.sb-item.active { background: var(--accent-dim); color: var(--accent); border-color: rgba(37,99,235,.2); }
.sb-item svg { flex-shrink: 0; }
.sb-divider { height: 1px; background: var(--border); margin: 8px 4px; }
.sb-label { font-size: 11px; font-weight: 700; letter-spacing: .1em; text-transform: uppercase; color: var(--text3); padding: 8px 12px 3px; }
.sb-badge { margin-left: auto; background: var(--surface3); color: var(--text3); font-size: 11px; font-weight: 600; padding: 2px 7px; border-radius: 10px; }

/* Main */
.main { flex: 1; display: flex; flex-direction: column; overflow: hidden; min-width: 0; }

/* Toolbar */
.toolbar { display: flex; align-items: center; gap: 8px; padding: 10px 14px; background: var(--header); border-bottom: 1px solid var(--border); flex-shrink: 0; min-height: 52px; }
.toolbar-title { font-size: 15px; font-weight: 600; flex: 1; }
.filter-chips { display: flex; gap: 6px; flex-wrap: wrap; }
.chip { display: inline-flex; align-items: center; gap: 5px; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; cursor: pointer; border: 1px solid var(--border2); background: transparent; color: var(--text2); transition: all .12s; }
.chip:hover { background: var(--surface2); color: var(--text); }
.chip.active { background: var(--accent-dim); color: var(--accent); border-color: rgba(37,99,235,.3); }

/* File list */
.file-area { flex: 1; overflow-y: auto; padding-bottom: 40px; }
.file-item { display: flex; align-items: center; gap: 14px; padding: 11px 14px; border-bottom: 1px solid rgba(42,42,42,.6); transition: background .08s; position: relative; user-select: none; -webkit-user-select: none; }
.file-item:hover { background: var(--surface2); }
.file-item.sel { background: rgba(37,99,235,.1); }

/* Icon bubble */
.icon-bg { display: flex; align-items: center; justify-content: center; width: 44px; height: 44px; border-radius: 50%; flex-shrink: 0; box-shadow: 0 2px 8px rgba(0,0,0,.3); }
.icon-bg svg { width: 22px; height: 22px; color: white; stroke: white; }

/* File info */
.fi-info { flex: 1; min-width: 0; }
.fi-name { font-size: 15px; font-weight: 400; color: var(--text); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.fi-meta { display: flex; gap: 10px; align-items: center; margin-top: 3px; flex-wrap: wrap; }
.fi-type { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: .05em; padding: 2px 7px; border-radius: 6px; }
.fi-size { font-size: 12px; color: var(--text3); }
.fi-date { font-size: 12px; color: var(--text3); margin-left: auto; white-space: nowrap; }
.fi-tags { display: flex; gap: 4px; flex-wrap: wrap; margin-top: 4px; }
.fi-tag { font-size: 11px; padding: 2px 8px; border-radius: 10px; background: rgba(37,99,235,.15); color: var(--accent); border: 1px solid rgba(37,99,235,.25); cursor: pointer; }
.fi-tag:hover { background: rgba(37,99,235,.25); }

/* Action menu */
.fi-actions { display: flex; align-items: center; gap: 2px; opacity: 0; transition: opacity .15s; }
.file-item:hover .fi-actions { opacity: 1; }
.act-btn { width: 32px; height: 32px; border-radius: var(--r8); border: none; background: transparent; color: var(--text3); cursor: pointer; display: flex; align-items: center; justify-content: center; transition: all .12s; }
.act-btn:hover { background: var(--surface3); color: var(--text); }
.act-btn.danger:hover { background: rgba(239,68,68,.15); color: var(--red); }

/* Checkbox */
.fi-cb { display: none; width: 20px; height: 20px; flex-shrink: 0; align-items: center; justify-content: center; }
.custom-cb { width: 20px; height: 20px; border-radius: 50%; border: 2px solid var(--border2); background: transparent; display: flex; align-items: center; justify-content: center; cursor: pointer; transition: all .18s; flex-shrink: 0; position: relative; }
.custom-cb.checked { background: var(--accent); border-color: var(--accent); }
.custom-cb.checked::after { content: ''; width: 7px; height: 4px; border-left: 2px solid #fff; border-bottom: 2px solid #fff; transform: rotate(-45deg) translateY(-1px); display: block; }
body.select-mode .fi-cb { display: flex; }

/* Empty state */
.empty { display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 80px 24px; gap: 16px; color: var(--text3); }
.empty svg { opacity: .3; }
.empty h3 { font-size: 20px; font-weight: 600; color: var(--text2); }
.empty p { font-size: 14px; }

/* Skeleton */
.sk { background: linear-gradient(90deg, var(--surface) 25%, var(--surface3) 50%, var(--surface) 75%); background-size: 200% 100%; animation: sk 1.4s infinite; border-radius: var(--r4); }
@keyframes sk { 0% { background-position: 200% 0 } 100% { background-position: -200% 0 } }

/* Selection bar */
#selbar { position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%) translateY(100px); background: var(--surface2); border: 1px solid var(--border2); border-radius: 36px; padding: 10px 14px; display: flex; align-items: center; gap: 6px; box-shadow: 0 8px 40px rgba(0,0,0,.7); z-index: 500; opacity: 0; pointer-events: none; transition: transform .28s cubic-bezier(.34,1.56,.64,1), opacity .18s; max-width: calc(100vw - 32px); }
#selbar.show { transform: translateX(-50%) translateY(0); opacity: 1; pointer-events: auto; }
#selcnt { font-size: 13px; color: var(--text2); padding: 0 4px; white-space: nowrap; }
.selbar-sep { width: 1px; height: 22px; background: var(--border2); margin: 0 2px; flex-shrink: 0; }
.sel-btn { display: flex; flex-direction: column; align-items: center; gap: 2px; background: transparent; border: none; cursor: pointer; padding: 6px 8px; border-radius: var(--r8); color: var(--text2); transition: all .12s; flex-shrink: 0; }
.sel-btn:hover { background: var(--surface3); color: var(--text); }
.sel-btn.danger { color: var(--red); }
.sel-btn.danger:hover { background: rgba(239,68,68,.15); }
.sel-btn span { font-size: 10px; font-weight: 600; white-space: nowrap; }
.sel-close { width: 30px; height: 30px; border-radius: 50%; background: var(--surface3); border: none; cursor: pointer; display: flex; align-items: center; justify-content: center; color: var(--text3); flex-shrink: 0; }
.sel-close:hover { color: var(--text); background: var(--border2); }

/* Modal */
.moverlay { display: none; position: fixed; inset: 0; background: rgba(0,0,0,.75); backdrop-filter: blur(6px); z-index: 1000; align-items: center; justify-content: center; padding: 16px; }
.moverlay.open { display: flex; }
.modal { background: var(--surface); border: 1px solid var(--border2); border-radius: var(--r16); padding: 24px 22px; width: 100%; max-width: 420px; box-shadow: var(--shadow); animation: mIn .2s ease; max-height: 88vh; overflow-y: auto; }
@keyframes mIn { from { transform: scale(.95) translateY(-8px); opacity: 0; } }
.modal-title { font-size: 16px; font-weight: 700; margin-bottom: 16px; display: flex; align-items: center; gap: 9px; color: var(--text); }
.fg { margin-bottom: 14px; }
.fg label { display: block; font-size: 11px; color: var(--text3); margin-bottom: 5px; text-transform: uppercase; letter-spacing: .05em; font-weight: 600; }
.macts { display: flex; gap: 8px; justify-content: flex-end; margin-top: 18px; }

/* Login */
.lp { min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; background: radial-gradient(ellipse at top, rgba(37,99,235,.07) 0%, transparent 60%); }
.lcard { background: var(--header); border: 1px solid var(--border2); border-radius: var(--r16); padding: 40px 32px; width: 100%; max-width: 380px; box-shadow: var(--shadow); }
.llogo { text-align: center; margin-bottom: 32px; }
.llogo h1 { font-size: 26px; font-weight: 800; margin-top: 12px; }
.llogo p { color: var(--text2); font-size: 14px; margin-top: 6px; }
.lerr { background: rgba(239,68,68,.1); border: 1px solid rgba(239,68,68,.3); border-radius: var(--r8); padding: 12px 14px; color: var(--red); font-size: 14px; margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }
.lhint { font-size: 12px; color: var(--text3); text-align: center; margin-top: 20px; line-height: 1.6; }

/* Stats row */
.stats-row { display: flex; gap: 12px; padding: 12px 14px; border-bottom: 1px solid var(--border); flex-shrink: 0; }
.stat-card { flex: 1; background: var(--surface2); border: 1px solid var(--border); border-radius: var(--r8); padding: 10px 14px; }
.stat-num { font-size: 20px; font-weight: 800; color: var(--text); }
.stat-label { font-size: 11px; color: var(--text3); font-weight: 600; text-transform: uppercase; letter-spacing: .05em; margin-top: 2px; }

/* Tags page */
.tags-grid { display: flex; flex-wrap: wrap; gap: 8px; padding: 16px; }
.tag-card { display: flex; align-items: center; gap: 8px; padding: 8px 14px; background: var(--surface2); border: 1px solid var(--border2); border-radius: 20px; cursor: pointer; transition: all .12s; font-size: 13px; font-weight: 500; color: var(--text2); }
.tag-card:hover { background: var(--accent-dim); color: var(--accent); border-color: rgba(37,99,235,.3); }
.tag-card .tag-count { font-size: 11px; background: var(--surface3); padding: 2px 7px; border-radius: 10px; color: var(--text3); }

/* Responsive */
@media (max-width: 640px) {
  .sidebar { display: none; }
  nav { padding: 0 10px; gap: 6px; }
  .stats-row { gap: 8px; padding: 10px; }
  .stat-num { font-size: 17px; }
}
"""


# ── JS ────────────────────────────────────────────────────────────────────────

_JS = """
function toast(msg, type='') {
  const t = document.getElementById('toast');
  t.textContent = msg; t.className = 'show ' + type;
  clearTimeout(t._t); t._t = setTimeout(() => t.className = '', 3500);
}
function bar(on) {
  const b = document.getElementById('bar');
  b.className = on ? 'on' : 'done';
  if (!on) setTimeout(() => b.className = '', 800);
}
function openModal(id) { document.getElementById('m-' + id).classList.add('open'); }
function closeModal(id) { document.getElementById('m-' + id).classList.remove('open'); }
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.moverlay').forEach(el =>
    el.addEventListener('click', e => { if (e.target === el) el.classList.remove('open'); })
  );
});
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') document.querySelectorAll('.moverlay.open').forEach(m => m.classList.remove('open'));
});
"""


# ── Page shell ────────────────────────────────────────────────────────────────

def _page(body: str, title: str = "SecureBox") -> web.Response:
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<title>{title} — SecureBox</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>{_CSS}</style>
</head><body>
<div id="bar"></div>
<div id="toast"></div>
{body}
<script>{_JS}</script>
</body></html>"""
    return web.Response(text=html, content_type="text/html")


# ── Login ─────────────────────────────────────────────────────────────────────

async def handle_login(request: web.Request) -> web.Response:
    tok = request.cookies.get("session")
    if tok and _verify(tok):
        raise web.HTTPFound("/files")

    error = ""
    if request.method == "POST":
        data = await request.post()
        pw = data.get("password", "")
        stored_hash = WEBUI_PASSWORD
        if not stored_hash:
            # No password set — check env directly
            stored_hash = os.getenv("WEBUI_PASSWORD_HASH", "")
        if stored_hash and _hash_pw(pw) == stored_hash:
            # Find first user id in db
            db = request.app["db"]
            first_file = await db.files_collection.find_one({})
            uid = first_file["user_id"] if first_file else 0
            resp = web.HTTPFound("/files")
            resp.set_cookie("session", _make_token(uid), max_age=86400 * 7, httponly=True, samesite="Lax")
            raise resp
        elif not stored_hash:
            error = "No password configured. Set WEBUI_PASSWORD_HASH in .env"
        else:
            error = "Incorrect password."

    err_html = f'<div class="lerr">{_icon("alert", 16)} {error}</div>' if error else ""
    return _page(f"""
<div class="lp">
  <div class="lcard">
    <div class="llogo">
      <div style="display:flex;justify-content:center">{_icon("shield", 52, "", None)}</div>
      <h1>SecureBox</h1>
      <p>Sign in to manage your Telegram files</p>
    </div>
    {err_html}
    <form method="POST">
      <div class="fg">
        <label>Password</label>
        <input name="password" type="password" placeholder="Enter your WebUI password" autofocus autocomplete="current-password">
      </div>
      <button type="submit" class="btn btn-primary btn-wide" style="height:46px;margin-top:8px;font-size:16px">
        {_icon("login", 18)} Sign In
      </button>
    </form>
    <p class="lhint">Set <code>WEBUI_PASSWORD_HASH</code> in your .env file<br>Generate with: <code>python3 gen_password.py</code></p>
  </div>
</div>""", "Sign in")


async def handle_logout(request: web.Request) -> web.Response:
    resp = web.HTTPFound("/")
    resp.del_cookie("session")
    raise resp


# ── File browser ──────────────────────────────────────────────────────────────

def _type_color(ft: str) -> str:
    colors = {
        "photo": "#a78bfa", "video": "#f87171", "video_note": "#fb923c",
        "audio": "#e55835", "voice": "#f59e0b",
        "document": "#60a5fa", "sticker": "#34d399",
    }
    return colors.get(ft, "#607d8b")


@require_auth
async def handle_files(request: web.Request) -> web.Response:
    uid = request["uid"]
    db = request.app["db"]

    # Stats
    total = await db.files_collection.count_documents({"user_id": uid})
    by_type = {}
    async for doc in db.files_collection.aggregate([
        {"$match": {"user_id": uid}},
        {"$group": {"_id": "$file_type", "count": {"$sum": 1}, "size": {"$sum": "$file_size"}}}
    ]):
        by_type[doc["_id"]] = {"count": doc["count"], "size": doc["size"]}

    total_size = sum(v["size"] for v in by_type.values() if v.get("size"))

    type_chips = ""
    type_order = ["document", "photo", "video", "video_note", "audio", "voice", "sticker"]
    for ft in type_order:
        if ft in by_type:
            label = ft.replace("_", " ").title()
            type_chips += f'<span class="chip" data-type="{ft}" onclick="filterType(this)">{label} <span style="opacity:.6">{by_type[ft]["count"]}</span></span>'

    skel = "".join(f"""<div class="file-item">
      <div class="sk" style="width:44px;height:44px;border-radius:50%;flex-shrink:0"></div>
      <div class="fi-info">
        <div class="sk" style="height:14px;width:55%;margin-bottom:7px"></div>
        <div class="sk" style="height:11px;width:30%"></div>
      </div>
    </div>""" for _ in range(8))

    type_sidebar_items = "".join(
        '<div class="sb-item" onclick="filterTypeSb(\'' + ft + '\')">'
        + _file_icon(ft, 16) + ' ' + ft.replace("_", " ").title()
        + ' <span class="sb-badge">' + str(by_type[ft]["count"]) + '</span></div>'
        for ft in type_order if ft in by_type
    )

    return _page(f"""
<nav>
  <a href="/files" class="nav-logo">
    {_icon("shield", 22)} SecureBox
  </a>
  <div class="nav-center">
    <div class="nav-search-wrap">
      {_icon("search", 16)}
      <input id="nav-search" type="text" placeholder="Search by name or tag…" oninput="onSearch(this.value)" onkeydown="if(event.key==='Enter')doSearch()">
    </div>
  </div>
  <a href="/logout" class="btn btn-ghost btn-sm">{_icon("signout", 16)} Sign out</a>
</nav>

<div class="layout">
  <aside class="sidebar">
    <div class="sb-item active" id="sb-all" onclick="showAll()">
      {_icon("home", 18)} All Files
      <span class="sb-badge">{total}</span>
    </div>
    <div class="sb-item" onclick="window.location='/tags'">
      {_icon("tag", 18)} Tags
    </div>
    <div class="sb-divider"></div>
    <div class="sb-label">File Types</div>
    {type_sidebar_items}
  </aside>

  <div class="main">
    <!-- Stats -->
    <div class="stats-row">
      <div class="stat-card">
        <div class="stat-num">{total}</div>
        <div class="stat-label">Total Files</div>
      </div>
      {"".join(f'<div class="stat-card"><div class="stat-num" style="color:{_type_color(ft)}">{by_type[ft]["count"]}</div><div class="stat-label">{ft.replace("_"," ").title()}</div></div>' for ft in type_order if ft in by_type)}
      <div class="stat-card">
        <div class="stat-num">{_fmt_size(total_size)}</div>
        <div class="stat-label">Total Size</div>
      </div>
    </div>

    <!-- Toolbar -->
    <div class="toolbar">
      <span class="toolbar-title" id="toolbar-title">All Files</span>
      <div class="filter-chips" id="type-chips">
        {type_chips}
      </div>
    </div>

    <!-- File list -->
    <div class="file-area" id="file-area">
      <div id="fl">{skel}</div>
    </div>
  </div>
</div>

<!-- Rename modal -->
<div class="moverlay" id="m-rename"><div class="modal">
  <div class="modal-title">{_icon("rename", 18)} Rename File</div>
  <div class="fg"><label>New name</label><input id="i-rename" type="text"></div>
  <div class="macts">
    <button class="btn btn-ghost btn-sm" onclick="closeModal('rename')">Cancel</button>
    <button class="btn btn-primary btn-sm" onclick="doRename()">Rename</button>
  </div>
</div></div>

<!-- Tag modal -->
<div class="moverlay" id="m-tag"><div class="modal">
  <div class="modal-title">{_icon("tag", 18)} Edit Tags</div>
  <div class="fg">
    <label>Tags (comma-separated)</label>
    <input id="i-tag" type="text" placeholder="work, important, tutorial">
  </div>
  <div class="macts">
    <button class="btn btn-ghost btn-sm" onclick="closeModal('tag')">Cancel</button>
    <button class="btn btn-primary btn-sm" onclick="doTag()">Save Tags</button>
  </div>
</div></div>

<!-- Delete modal -->
<div class="moverlay" id="m-delete"><div class="modal">
  <div class="modal-title">{_icon("delete", 18)} Delete File</div>
  <p id="del-msg" style="color:var(--text2);font-size:14px;margin-bottom:6px"></p>
  <p style="font-size:12px;color:var(--text3)">This action cannot be undone.</p>
  <div class="macts">
    <button class="btn btn-ghost btn-sm" onclick="closeModal('delete')">Cancel</button>
    <button class="btn btn-danger btn-sm" onclick="doDelete()">Delete</button>
  </div>
</div></div>

<!-- Bulk delete modal -->
<div class="moverlay" id="m-bulk-delete"><div class="modal">
  <div class="modal-title">{_icon("delete", 18)} Delete Files</div>
  <p id="bulk-del-msg" style="color:var(--text2);font-size:14px;margin-bottom:6px"></p>
  <div class="macts">
    <button class="btn btn-ghost btn-sm" onclick="closeModal('bulk-delete')">Cancel</button>
    <button class="btn btn-danger btn-sm" onclick="doBulkDelete()">Delete All</button>
  </div>
</div></div>

<!-- Bulk tag modal -->
<div class="moverlay" id="m-bulk-tag"><div class="modal">
  <div class="modal-title">{_icon("tag", 18)} Add Tags to Selected</div>
  <div class="fg">
    <label>Tags (comma-separated)</label>
    <input id="i-bulk-tag" type="text" placeholder="work, important">
  </div>
  <div class="macts">
    <button class="btn btn-ghost btn-sm" onclick="closeModal('bulk-tag')">Cancel</button>
    <button class="btn btn-primary btn-sm" onclick="doBulkTag()">Add Tags</button>
  </div>
</div></div>

<!-- Selection bar -->
<div id="selbar">
  <button class="sel-close" onclick="clearSel()">{_icon("close", 14)}</button>
  <span id="selcnt">0 selected</span>
  <div class="selbar-sep"></div>
  <button class="sel-btn" onclick="bulkTag()">{_icon("tag", 20)}<span>Tag</span></button>
  <button class="sel-btn danger" onclick="bulkDelete()">{_icon("delete", 20)}<span>Delete</span></button>
</div>

<script>
let files = [], sel = new Set(), currentFilter = '', searchQ = '';
let renameId = null, deleteId = null;

function sz(b) {{
  if (!b) return '—';
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b/1024).toFixed(1) + ' KB';
  if (b < 1073741824) return (b/1048576).toFixed(1) + ' MB';
  return (b/1073741824).toFixed(2) + ' GB';
}}
function dt(s) {{
  if (!s) return '—';
  const d = new Date(s * 1000);
  const now = new Date();
  if (now - d < 86400000) return d.toLocaleTimeString([], {{hour: '2-digit', minute: '2-digit'}});
  return d.toLocaleDateString([], {{year: 'numeric', month: 'short', day: 'numeric'}});
}}
const TYPE_COLORS = {{
  photo: '#a78bfa', video: '#f87171', video_note: '#fb923c',
  audio: '#e55835', voice: '#f59e0b', document: '#60a5fa', sticker: '#34d399'
}};
const TYPE_ICONS = {{
  photo: 'image', video: 'video', video_note: 'video',
  audio: 'audio', voice: 'audio', document: 'document', sticker: 'sticker'
}};
const ICON_SVGS = {{
  image: '<path d="M2.25 15.75l5.159-5.159a2.25 2.25 0 013.182 0l5.159 5.159m-1.5-1.5l1.409-1.409a2.25 2.25 0 013.182 0l2.909 2.909m-18 3.75h16.5a1.5 1.5 0 001.5-1.5V6a1.5 1.5 0 00-1.5-1.5H3.75A1.5 1.5 0 002.25 6v12a1.5 1.5 0 001.5 1.5zm10.5-11.25h.008v.008h-.008V8.25zm.375 0a.375.375 0 11-.75 0 .375.375 0 01.75 0z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
  video: '<path d="M15.75 10.5l4.72-4.72a.75.75 0 011.28.53v11.38a.75.75 0 01-1.28.53l-4.72-4.72M4.5 18.75h9a2.25 2.25 0 002.25-2.25v-9a2.25 2.25 0 00-2.25-2.25h-9A2.25 2.25 0 002.25 7.5v9a2.25 2.25 0 002.25 2.25z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
  audio: '<path d="M9 9l10.5-3m0 6.553v3.75a2.25 2.25 0 01-1.632 2.163l-1.32.377a1.803 1.803 0 11-.99-3.467l2.31-.66a2.25 2.25 0 001.632-2.163zm0 0V2.25L9 5.25v10.303m0 0v3.75a2.25 2.25 0 01-1.632 2.163l-1.32.377a1.803 1.803 0 01-.99-3.467l2.31-.66A2.25 2.25 0 009 15.553z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
  document: '<path d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m2.25 0H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
  sticker: '<path d="M15.182 15.182a4.5 4.5 0 01-6.364 0M21 12a9 9 0 11-18 0 9 9 0 0118 0zM9.75 9.75c0 .414-.168.75-.375.75S9 10.164 9 9.75 9.168 9 9.375 9s.375.336.375.75zm-.375 0h.008v.015h-.008V9.75zm5.625 0c0 .414-.168.75-.375.75s-.375-.336-.375-.75.168-.75.375-.75.375.336.375.75zm-.375 0h.008v.015h-.008V9.75z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
  file: '<path d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m2.25 0H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>'
}};

function getIco(ft) {{
  const n = TYPE_ICONS[ft] || 'file';
  const c = TYPE_COLORS[ft] || '#607d8b';
  return `<div class="icon-bg" style="background-color:${{c}}"><svg width="22" height="22" viewBox="0 0 24 24" fill="none">${{ICON_SVGS[n] || ICON_SVGS.file}}</svg></div>`;
}}

async function load() {{
  bar(true);
  const fl = document.getElementById('fl');
  fl.innerHTML = Array(6).fill(`<div class="file-item"><div class="sk" style="width:44px;height:44px;border-radius:50%;flex-shrink:0"></div><div class="fi-info"><div class="sk" style="height:14px;width:55%;margin-bottom:7px"></div><div class="sk" style="height:11px;width:30%"></div></div></div>`).join('');
  try {{
    let url = '/api/files';
    const params = [];
    if (currentFilter) params.push('type=' + currentFilter);
    if (searchQ) params.push('q=' + encodeURIComponent(searchQ));
    if (params.length) url += '?' + params.join('&');
    const r = await fetch(url);
    const d = await r.json();
    files = d.files || [];
    render();
  }} catch(e) {{
    fl.innerHTML = `<div class="empty"><svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z"/></svg><h3>Failed to load</h3><p>${{e.message}}</p></div>`;
  }}
  bar(false);
}}

function render() {{
  const fl = document.getElementById('fl');
  if (!files.length) {{
    fl.innerHTML = `<div class="empty"><svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m2.25 0H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z"/></svg><h3>No files found</h3><p>Send files to your Telegram bot to get started</p></div>`;
    return;
  }}
  fl.innerHTML = files.map(f => fileItemHTML(f)).join('');
}}

function fileItemHTML(f) {{
  const nm = (f.file_name || 'Unnamed').replace(/"/g, '&quot;');
  const tags = (f.tags || []).map(t => `<span class="fi-tag" onclick="event.stopPropagation();filterTag('${{t}}')">${{t}}</span>`).join('');
  const tagsRow = tags ? `<div class="fi-tags">${{tags}}</div>` : '';
  const selCls = sel.has(f._id) ? ' sel' : '';
  const cbCls = sel.has(f._id) ? 'custom-cb checked' : 'custom-cb';
  const c = TYPE_COLORS[f.file_type] || '#607d8b';
  return `<div class="file-item${{selCls}}" data-id="${{f._id}}">
    <div class="fi-cb" onclick="event.stopPropagation();toggleSel('${{f._id}}',this.querySelector('.custom-cb'))">
      <div class="${{cbCls}}"></div>
    </div>
    ${{getIco(f.file_type)}}
    <div class="fi-info">
      <div class="fi-name">${{f.file_name || 'Unnamed'}}</div>
      <div class="fi-meta">
        <span class="fi-type" style="background:${{c}}22;color:${{c}}">${{(f.file_type||'?').replace('_',' ')}}</span>
        <span class="fi-size">${{sz(f.file_size)}}</span>
        <span class="fi-date">${{dt(f.message_date)}}</span>
      </div>
      ${{tagsRow}}
    </div>
    <div class="fi-actions">
      <button class="act-btn" title="Rename" onclick="openRename('${{f._id}}','${{nm}}')">${{ICON_SVGS_SMALL.rename}}</button>
      <button class="act-btn" title="Edit tags" onclick="openTag('${{f._id}}','${{(f.tags||[]).join(', ')}}')">${{ICON_SVGS_SMALL.tag}}</button>
      <button class="act-btn danger" title="Delete" onclick="openDelete('${{f._id}}','${{nm}}')">${{ICON_SVGS_SMALL.delete}}</button>
    </div>
  </div>`;
}}

const ICON_SVGS_SMALL = {{
  rename: `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><path d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L6.832 19.82a4.5 4.5 0 01-1.897 1.13l-2.685.8.8-2.685a4.5 4.5 0 011.13-1.897L16.863 4.487zm0 0L19.5 7.125"/></svg>`,
  tag:    `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><path d="M9.568 3H5.25A2.25 2.25 0 003 5.25v4.318c0 .597.237 1.17.659 1.591l9.581 9.581c.699.699 1.78.872 2.607.33a18.095 18.095 0 005.223-5.223c.542-.827.369-1.908-.33-2.607L11.16 3.66A2.25 2.25 0 009.568 3z"/><path d="M6 6h.008v.008H6V6z"/></svg>`,
  delete: `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><path d="M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 01-2.244 2.077H8.084a2.25 2.25 0 01-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 00-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 013.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 00-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 00-7.5 0"/></svg>`,
}};

function filterType(el) {{
  const t = el.dataset.type;
  if (currentFilter === t) {{ currentFilter = ''; el.classList.remove('active'); }}
  else {{
    document.querySelectorAll('.chip').forEach(c => c.classList.remove('active'));
    currentFilter = t; el.classList.add('active');
  }}
  updateTitle();
  load();
}}
function filterTypeSb(t) {{
  currentFilter = t;
  document.querySelectorAll('.chip').forEach(c => c.classList.toggle('active', c.dataset.type === t));
  updateTitle();
  load();
  document.querySelectorAll('.sb-item').forEach(s => s.classList.remove('active'));
}}
function showAll() {{
  currentFilter = ''; searchQ = '';
  document.getElementById('nav-search').value = '';
  document.querySelectorAll('.chip').forEach(c => c.classList.remove('active'));
  document.querySelectorAll('.sb-item').forEach(s => s.classList.remove('active'));
  document.getElementById('sb-all').classList.add('active');
  updateTitle();
  load();
}}
function filterTag(tag) {{
  searchQ = tag;
  document.getElementById('nav-search').value = tag;
  load();
}}
function onSearch(v) {{ searchQ = v; if (!v) load(); }}
function doSearch() {{ load(); }}
function updateTitle() {{
  const t = document.getElementById('toolbar-title');
  if (searchQ) t.textContent = `Search: "${{searchQ}}"`;
  else if (currentFilter) t.textContent = currentFilter.replace('_', ' ').split(' ').map(function(w){{return w.charAt(0).toUpperCase()+w.slice(1)}}).join(' ') + ' Files';
  else t.textContent = 'All Files';
}}

function openRename(id, name) {{
  renameId = id;
  document.getElementById('i-rename').value = name;
  openModal('rename');
  setTimeout(() => document.getElementById('i-rename').select(), 60);
}}
async function doRename() {{
  const name = document.getElementById('i-rename').value.trim(); if (!name) return;
  closeModal('rename'); bar(true);
  const r = await fetch('/api/rename/' + renameId, {{method: 'POST', headers: {{'Content-Type': 'application/json'}}, body: JSON.stringify({{name}})}});
  bar(false); r.ok ? toast('File renamed', 'ok') : toast('Failed to rename', 'err');
  load();
}}

function openTag(id, tagsStr) {{
  renameId = id;
  document.getElementById('i-tag').value = tagsStr;
  openModal('tag');
  setTimeout(() => document.getElementById('i-tag').focus(), 60);
}}
async function doTag() {{
  const tags = document.getElementById('i-tag').value.split(',').map(t => t.trim()).filter(Boolean);
  closeModal('tag'); bar(true);
  const r = await fetch('/api/tag/' + renameId, {{method: 'POST', headers: {{'Content-Type': 'application/json'}}, body: JSON.stringify({{tags}})}});
  bar(false); r.ok ? toast('Tags updated', 'ok') : toast('Failed to update tags', 'err');
  load();
}}

function openDelete(id, name) {{
  deleteId = id;
  document.getElementById('del-msg').textContent = `Delete "${{name}}"?`;
  openModal('delete');
}}
async function doDelete() {{
  closeModal('delete'); bar(true);
  const r = await fetch('/api/delete/' + deleteId, {{method: 'POST'}});
  bar(false); r.ok ? toast('File deleted', 'ok') : toast('Failed to delete', 'err');
  load();
}}

// Selection
function toggleSel(id, cb) {{
  const isChecked = cb.classList.contains('checked');
  if (isChecked) {{ cb.classList.remove('checked'); sel.delete(id); }}
  else {{ cb.classList.add('checked'); sel.add(id); document.body.classList.add('select-mode'); }}
  document.querySelector(`[data-id="${{id}}"]`)?.classList.toggle('sel', !isChecked);
  updateSel();
}}
function updateSel() {{
  const b = document.getElementById('selbar');
  document.getElementById('selcnt').textContent = sel.size + ' selected';
  b.classList.toggle('show', sel.size > 0);
  if (sel.size === 0) document.body.classList.remove('select-mode');
}}
function clearSel() {{
  sel.clear();
  document.querySelectorAll('.custom-cb').forEach(c => c.classList.remove('checked'));
  document.querySelectorAll('.file-item.sel').forEach(r => r.classList.remove('sel'));
  document.body.classList.remove('select-mode');
  updateSel();
}}

function bulkDelete() {{
  if (!sel.size) return;
  document.getElementById('bulk-del-msg').textContent = `Delete ${{sel.size}} selected file${{sel.size > 1 ? 's' : ''}}?`;
  openModal('bulk-delete');
}}
async function doBulkDelete() {{
  closeModal('bulk-delete'); bar(true);
  await Promise.all([...sel].map(id => fetch('/api/delete/' + id, {{method: 'POST'}})));
  bar(false); toast(`Deleted ${{sel.size}} file(s)`, 'ok');
  clearSel(); load();
}}

function bulkTag() {{
  if (!sel.size) return;
  document.getElementById('i-bulk-tag').value = '';
  openModal('bulk-tag');
}}
async function doBulkTag() {{
  const tags = document.getElementById('i-bulk-tag').value.split(',').map(t => t.trim()).filter(Boolean);
  closeModal('bulk-tag'); bar(true);
  await Promise.all([...sel].map(id => fetch('/api/tag/' + id, {{method: 'POST', headers: {{'Content-Type': 'application/json'}}, body: JSON.stringify({{tags, merge: true}})}})));
  bar(false); toast(`Tags added to ${{sel.size}} file(s)`, 'ok');
  clearSel(); load();
}}

document.addEventListener('keydown', e => {{
  if (e.key === 'Enter') {{
    if (document.getElementById('m-rename').classList.contains('open')) doRename();
    else if (document.getElementById('m-tag').classList.contains('open')) doTag();
    else if (document.getElementById('nav-search') === document.activeElement) doSearch();
  }}
}});

load();
</script>
""", "Files")


# ── Tags page ─────────────────────────────────────────────────────────────────

@require_auth
async def handle_tags(request: web.Request) -> web.Response:
    uid = request["uid"]
    db = request.app["db"]

    # Aggregate tags from files collection
    pipeline = [
        {"$match": {"user_id": uid}},
        {"$unwind": "$tags"},
        {"$group": {"_id": "$tags", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]
    tags = []
    async for doc in db.files_collection.aggregate(pipeline):
        tags.append({"tag": doc["_id"], "count": doc["count"]})

    tags_html = ""
    for t in tags:
        tags_html += f'<div class="tag-card" onclick="window.location=\'/files?tag={t["tag"]}\'">{_icon("tag", 14)} {t["tag"]} <span class="tag-count">{t["count"]}</span></div>'

    if not tags_html:
        tags_html = '<p style="color:var(--text3);padding:24px">No tags yet. Add tags to your files via the Telegram bot or the file manager.</p>'

    return _page(f"""
<nav>
  <a href="/files" class="nav-logo">{_icon("shield", 22)} SecureBox</a>
  <div class="nav-center"></div>
  <a href="/logout" class="btn btn-ghost btn-sm">{_icon("signout", 16)} Sign out</a>
</nav>
<div class="layout">
  <aside class="sidebar">
    <div class="sb-item" onclick="window.location='/files'">{_icon("home", 18)} All Files</div>
    <div class="sb-item active">{_icon("tag", 18)} Tags</div>
  </aside>
  <div class="main">
    <div class="toolbar">
      <span class="toolbar-title">Tags ({len(tags)})</span>
    </div>
    <div class="file-area">
      <div class="tags-grid">{tags_html}</div>
    </div>
  </div>
</div>
""", "Tags")


# ── API: list files ───────────────────────────────────────────────────────────

@require_auth
async def api_files(request: web.Request) -> web.Response:
    uid = request["uid"]
    db = request.app["db"]
    file_type = request.rel_url.query.get("type", "")
    q = request.rel_url.query.get("q", "").strip()
    tag = request.rel_url.query.get("tag", "").strip()

    filt: dict = {"user_id": uid}
    if file_type:
        filt["file_type"] = file_type
    if q:
        filt["$or"] = [
            {"file_name": {"$regex": q, "$options": "i"}},
            {"tags": {"$regex": q, "$options": "i"}},
        ]
    if tag:
        filt["tags"] = tag

    cursor = db.files_collection.find(filt).sort("message_date", -1).limit(200)
    files = []
    async for doc in cursor:
        files.append({
            "_id": str(doc["_id"]),
            "file_id": doc.get("file_id"),
            "file_name": doc.get("file_name", "Unnamed"),
            "file_size": doc.get("file_size"),
            "file_type": doc.get("file_type", "document"),
            "tags": doc.get("tags", []),
            "message_date": int(doc["message_date"].timestamp()) if doc.get("message_date") else None,
        })
    return web.json_response({"files": files})


# ── API: rename ───────────────────────────────────────────────────────────────

@require_auth
async def api_rename(request: web.Request) -> web.Response:
    fid = request.match_info["fid"]
    body = await request.json()
    name = body.get("name", "").strip()
    if not name:
        raise web.HTTPBadRequest(reason="Name required")
    db = request.app["db"]
    await db.files_collection.update_one({"_id": ObjectId(fid)}, {"$set": {"file_name": name}})
    return web.json_response({"ok": True})


# ── API: tag ──────────────────────────────────────────────────────────────────

@require_auth
async def api_tag(request: web.Request) -> web.Response:
    fid = request.match_info["fid"]
    uid = request["uid"]
    body = await request.json()
    tags = body.get("tags", [])
    merge = body.get("merge", False)
    db = request.app["db"]

    if merge:
        await db.files_collection.update_one(
            {"_id": ObjectId(fid)},
            {"$addToSet": {"tags": {"$each": tags}}}
        )
    else:
        await db.files_collection.update_one(
            {"_id": ObjectId(fid)},
            {"$set": {"tags": tags}}
        )

    # Sync to tags_collection
    from datetime import datetime
    for tag in tags:
        await db.tags_collection.update_one(
            {"user_id": uid, "tag": tag},
            {"$setOnInsert": {"created_at": datetime.utcnow()}},
            upsert=True
        )
    return web.json_response({"ok": True})


# ── API: delete ───────────────────────────────────────────────────────────────

@require_auth
async def api_delete(request: web.Request) -> web.Response:
    fid = request.match_info["fid"]
    db = request.app["db"]
    result = await db.files_collection.delete_one({"_id": ObjectId(fid)})
    if result.deleted_count == 0:
        raise web.HTTPNotFound(reason="File not found")
    return web.json_response({"ok": True})


# ── App factory ───────────────────────────────────────────────────────────────

class DBWrapper:
    """Thin wrapper so webui can share the motor client."""
    def __init__(self, mongo_uri: str):
        client = AsyncIOMotorClient(mongo_uri)
        _db = client["file_store_bot"]
        self.files_collection = _db["files"]
        self.tags_collection = _db["tags"]


def create_app(mongo_uri: str) -> web.Application:
    app = web.Application()
    app["db"] = DBWrapper(mongo_uri)

    app.router.add_route("GET",  "/",              handle_login)
    app.router.add_route("POST", "/",              handle_login)
    app.router.add_get("/logout",                  handle_logout)
    app.router.add_get("/files",                   handle_files)
    app.router.add_get("/tags",                    handle_tags)
    app.router.add_get("/api/files",               api_files)
    app.router.add_post("/api/rename/{fid}",       api_rename)
    app.router.add_post("/api/tag/{fid}",          api_tag)
    app.router.add_post("/api/delete/{fid}",       api_delete)
    return app


if __name__ == "__main__":
    import os
    from dotenv import load_dotenv
    load_dotenv()
    logging.basicConfig(level=logging.INFO)
    MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    PORT = int(os.getenv("WEBUI_PORT", "8080"))
    app = create_app(MONGO_URI)
    web.run_app(app, host="0.0.0.0", port=PORT)
