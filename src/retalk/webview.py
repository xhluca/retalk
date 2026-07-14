"""Local web view for saved conversations (`retalk show --web`).

Serves a single-page, messenger-style UI over plain HTTP on 127.0.0.1: a
sidebar of conversations and a bubble thread pane, reading the same sealed
message store that `retalk show` and `retalk history` read. It never
contacts the relay — new messages appear when any other process saves them
(`send`/`receive --save`, `RETALK_SAVE_MESSAGE=1`, a `--follow` reader).

Message bodies are decrypted for display, so access is guarded two ways:
the server binds to 127.0.0.1 only, and every request must carry a random
per-run token (the printed URL includes it) — on a shared machine, other
local users cannot read the page without it.
"""

from __future__ import annotations

import hmac
import json
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>retalk</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root { --bg:#0e1418; --panel:#151d23; --line:#22303a; --ink:#dbe4ea;
          --dim:#7b8b96; --out:#1f4d3f; --in:#243441; --accent:#38b28c; }
  * { box-sizing:border-box; margin:0; }
  body { background:var(--bg); color:var(--ink); height:100vh; display:flex;
         font:14px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; }
  #side { width:280px; min-width:220px; background:var(--panel);
          border-right:1px solid var(--line); display:flex; flex-direction:column; }
  #side h1 { font-size:15px; padding:14px 16px; border-bottom:1px solid var(--line); }
  #side h1 small { color:var(--dim); font-weight:normal; }
  #convos { overflow-y:auto; flex:1; }
  .convo { padding:11px 16px; cursor:pointer; border-bottom:1px solid var(--line); }
  .convo:hover { background:#1a242c; }
  .convo.sel { background:#1e2b35; border-left:3px solid var(--accent); padding-left:13px; }
  .convo .nm { font-weight:600; }
  .convo .meta { color:var(--dim); font-size:12px; margin-top:2px;
                 white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  #main { flex:1; display:flex; flex-direction:column; min-width:0; }
  #head { padding:12px 18px; border-bottom:1px solid var(--line); background:var(--panel); }
  #head .nm { font-weight:600; }
  #head .fp { color:var(--dim); font-size:11px; font-family:ui-monospace,monospace; }
  #thread { flex:1; overflow-y:auto; padding:18px; display:flex; flex-direction:column; }
  .day { align-self:center; color:var(--dim); font-size:11px; margin:12px 0 4px;
         background:var(--panel); padding:2px 10px; border-radius:10px; }
  .msg { max-width:64%; padding:7px 11px; border-radius:12px; margin-top:6px;
         white-space:pre-wrap; overflow-wrap:break-word; }
  .msg .who { font-size:11px; color:var(--dim); margin-bottom:2px; }
  .msg .tm { font-size:10px; color:var(--dim); text-align:right; margin-top:3px; }
  .in  { background:var(--in);  align-self:flex-start; border-bottom-left-radius:3px; }
  .out { background:var(--out); align-self:flex-end;   border-bottom-right-radius:3px; }
  #empty { color:var(--dim); text-align:center; margin:auto; }
  #empty code { color:var(--ink); }
</style></head><body>
  <div id="side"><h1>💬 retalk · <span id="me"></span> <small>saved chats</small></h1>
    <div id="convos"></div></div>
  <div id="main">
    <div id="head"><span class="nm" id="peerName">—</span>
      <div class="fp" id="peerFp"></div></div>
    <div id="thread"><div id="empty">select a conversation</div></div>
  </div>
<script>
  const token = new URLSearchParams(location.search).get("t") || "";
  const hdrs = {"X-Retalk-Token": token};
  let sel = null, lastRow = 0, lastDay = "";

  async function api(path) {
    const r = await fetch(path, {headers: hdrs});
    if (!r.ok) throw new Error("api " + r.status);
    return r.json();
  }
  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }
  function fmtDay(ts) { return new Date(ts * 1000).toLocaleDateString(); }
  function fmtTime(ts) {
    return new Date(ts * 1000).toLocaleTimeString([], {hour: "2-digit", minute: "2-digit"});
  }

  async function refreshConvos() {
    const d = await api("/api/conversations");
    document.getElementById("me").textContent = d.me;
    const box = document.getElementById("convos");
    box.replaceChildren();
    for (const c of d.conversations) {
      const div = el("div", "convo" + (sel === c.fingerprint ? " sel" : ""));
      div.appendChild(el("div", "nm", c.name));
      const n = c.count === 1 ? "1 message" : c.count + " messages";
      div.appendChild(el("div", "meta", (c.count ? n : "nothing saved yet")
                         + " · " + c.fingerprint.slice(0, 12) + "…"));
      div.onclick = () => select(c.fingerprint, c.name);
      box.appendChild(div);
    }
    if (!sel && d.conversations.length)
      select(d.conversations[0].fingerprint, d.conversations[0].name);
  }

  function select(fp, name) {
    sel = fp; lastRow = 0; lastDay = "";
    document.getElementById("peerName").textContent = name;
    document.getElementById("peerFp").textContent = fp;
    document.getElementById("thread").replaceChildren();
    refreshConvos();
    poll();
  }

  async function poll() {
    if (!sel) return;
    const fp = sel;
    const d = await api("/api/messages?peer=" + fp + "&after=" + lastRow);
    if (fp !== sel) return;              // switched threads mid-fetch
    const t = document.getElementById("thread");
    const stick = t.scrollHeight - t.scrollTop - t.clientHeight < 60;
    for (const m of d.messages) {
      lastRow = Math.max(lastRow, m.rowid);
      const day = fmtDay(m.ts);
      if (day !== lastDay) { t.appendChild(el("div", "day", "📅 " + day)); lastDay = day; }
      const b = el("div", "msg " + (m.direction === "out" ? "out" : "in"));
      b.appendChild(el("div", "who", m.name));
      b.appendChild(el("div", null, m.text));
      b.appendChild(el("div", "tm", fmtTime(m.ts)));
      t.appendChild(b);
    }
    if (d.messages.length && (stick || t.childElementCount === d.messages.length))
      t.scrollTop = t.scrollHeight;
    if (!t.childElementCount)
      t.appendChild(el("div", "day", "nothing saved with this peer yet"));
  }

  refreshConvos();
  setInterval(refreshConvos, 5000);
  setInterval(poll, 2000);
</script></body></html>
"""


def start(port: int, me: str, conversations, messages):
    """Bind the web view on 127.0.0.1:PORT; returns (httpd, token, url).

    `conversations()` -> list of {fingerprint, name, count, last_ts};
    `messages(peer_fp, after_rowid)` -> list of {rowid, direction, name,
    text, ts}. Both run on the server thread per request, so they must
    reopen nothing and stay cheap. Caller runs httpd.serve_forever().
    """
    token = secrets.token_urlsafe(16)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):        # keep stdout/stderr clean
            pass

        def _send(self, code, body, ctype):
            data = body.encode() if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; style-src 'unsafe-inline'; "
                             "script-src 'unsafe-inline'; connect-src 'self'")
            self.end_headers()
            self.wfile.write(data)

        def _json(self, obj, code=200):
            self._send(code, json.dumps(obj), "application/json")

        def do_GET(self):
            parts = urlsplit(self.path)
            q = parse_qs(parts.query)
            got = self.headers.get("X-Retalk-Token") or (q.get("t") or [""])[0]
            if not hmac.compare_digest(got, token):
                self._json({"error": "missing or bad token"}, 403)
                return
            try:
                if parts.path == "/":
                    self._send(200, PAGE, "text/html; charset=utf-8")
                elif parts.path == "/api/conversations":
                    self._json({"me": me, "conversations": conversations()})
                elif parts.path == "/api/messages":
                    peer = (q.get("peer") or [""])[0]
                    after = int((q.get("after") or ["0"])[0])
                    self._json({"messages": messages(peer, after)})
                else:
                    self._json({"error": "not found"}, 404)
            except Exception as e:      # a broken row must not kill the server
                self._json({"error": str(e)}, 500)

    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{httpd.server_address[1]}/?t={token}"
    return httpd, token, url
