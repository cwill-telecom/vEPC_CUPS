#!/usr/bin/env python3
# core/webdash.py — a tiny stdlib web dashboard for the vEPC/EPC simulator.
#
# Serves a live status page (http://host:port/) that polls every node's text control
# socket (STATUS + optional extras) and renders it as cards, refreshing every 2s.
#
#   python3 core/webdash.py                # http://127.0.0.1:8080
#   python3 core/webdash.py --port 9000 --host 0.0.0.0
#
# Also exposed as a thread by run_epc.py / run_stack.py (--web PORT).
import argparse
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from network.udp_client import UDPClient
from utils.utils import log

# (name, ip, control_port, [extra commands])
DEFAULT_TARGETS = [
    ("UE",    "127.0.0.10", 8909, []),
    ("eNB",   "127.0.0.11", 8911, ["GTPSTAT"]),
    ("MME",   "127.0.0.12", 8910, ["UES"]),
    ("HSS",   "127.0.0.13", 8912, []),
    ("PCRF",  "127.0.0.14", 8913, []),
    ("SGW-C", "127.0.0.4",  8905, ["SESSIONS"]),
    ("PGW-C", "127.0.0.5",  8906, ["SESSIONS"]),
    ("SGW-U", "127.0.0.2",  8907, ["SESSIONS", "GTPSTAT"]),
    ("PGW-U", "127.0.0.3",  8908, ["SESSIONS", "GTPSTAT"]),
    ("PDN",   "127.0.0.15", 8914, []),
]


def query(ip, port, cmd, timeout=0.6):
    c = UDPClient()
    try:
        rep, _ = c.request(cmd.encode(), ip, port, timeout)
    except Exception:  # noqa
        rep = None
    finally:
        c.close()
    return rep.decode().strip() if rep else None


PAGE = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>vEPC / EPC — live state</title>
<style>
  :root{color-scheme:dark}
  *{box-sizing:border-box}
  body{margin:0;font:14px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
       background:#0d1117;color:#c9d1d9}
  header{padding:16px 22px;border-bottom:1px solid #21262d;display:flex;
         align-items:baseline;gap:14px;flex-wrap:wrap}
  h1{font-size:16px;margin:0;color:#e6edf3}
  .sub{color:#8b949e;font-size:12px}
  .ok{color:#3fb950}.bad{color:#f85149}.warn{color:#d29922}
  main{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));
       gap:14px;padding:16px 22px}
  .card{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:12px 14px}
  .card h2{font-size:13px;margin:0 0 8px;display:flex;justify-content:space-between;
           align-items:center}
  .card h2 .ip{color:#8b949e;font-weight:400;font-size:11px}
  .dot{width:8px;height:8px;border-radius:50%;display:inline-block;margin-right:6px}
  .d-up{background:#3fb950}.d-down{background:#f85149}
  table{width:100%;border-collapse:collapse}
  td{padding:2px 0;vertical-align:top}
  td.k{color:#8b949e;width:38%;white-space:nowrap}
  .raw{margin-top:8px;color:#6e7681;font-size:11px;word-break:break-all}
  .tag{color:#58a6ff}
  header .sub b{color:#c9d1d9}
</style></head>
<body>
<header>
  <h1>vEPC / EPC — live node state</h1>
  <span class="sub">updated <b id="ts">–</b> · auto-refresh 2s · nodes up:
    <b id="up">–</b></span>
</header>
<main id="grid"></main>
<script>
async function tick(){
  let data;
  try{ data = await (await fetch('/state.json',{cache:'no-store'})).json(); }
  catch(e){ document.getElementById('ts').textContent='dashboard error'; return; }
  const grid=document.getElementById('grid'); grid.innerHTML='';
  let up=0;
  for(const n of data){
    const alive = n.status && n.status.startsWith('OK');
    if(alive) up++;
    const card=document.createElement('div'); card.className='card';
    const h=document.createElement('h2');
    h.innerHTML='<span><span class="dot '+(alive?'d-up':'d-down')+'"></span>'+n.name
      +'</span><span class="ip">'+n.ip+':'+n.port+'</span>';
    card.appendChild(h);
    const t=document.createElement('table');
    const rows=[];
    if(!alive){ rows.push(['state','<span class="bad">no response</span>']); }
    else{
      const toks=n.status.split(/\s+/).slice(1);
      for(const tk of toks){ const i=tk.indexOf('='); if(i>0)
        rows.push([tk.slice(0,i), '<span class="tag">'+tk.slice(i+1)+'</span>']); }
    }
    for(const [cmd,val] of Object.entries(n.extras||{})){
      let v = val===null ? '<span class="warn">–</span>'
                         : '<span class="tag">'+val.replace(/^OK\s+\S+\s*/,'')+'</span>';
      rows.push([cmd.toLowerCase(), v]);
    }
    for(const [k,v] of rows){ const tr=document.createElement('tr');
      tr.innerHTML='<td class="k">'+k+'</td><td>'+v+'</td>'; t.appendChild(tr); }
    card.appendChild(t);
    const raw=document.createElement('div'); raw.className='raw';
    raw.textContent = n.status || 'no response';
    card.appendChild(raw);
    grid.appendChild(card);
  }
  document.getElementById('up').textContent = up+'/'+data.length;
  document.getElementById('ts').textContent = new Date().toLocaleTimeString();
}
tick(); setInterval(tick, 2000);
</script>
</body></html>"""


class Dashboard:
    def __init__(self, host="127.0.0.1", port=8080, targets=None):
        self.host = host
        self.port = port
        self.targets = targets or DEFAULT_TARGETS
        self.httpd = ThreadingHTTPServer((host, port), self._handler())
        self._thread = None

    def state(self):
        out = []
        for name, ip, port, extras in self.targets:
            out.append({
                "name": name, "ip": ip, "port": port,
                "status": query(ip, port, "STATUS"),
                "extras": {e: query(ip, port, e) for e in extras},
            })
        return out

    def _handler(self):
        dash = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):  # quiet
                pass

            def _send(self, body, ctype):
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if self.path.startswith("/state.json"):
                    self._send(json.dumps(dash.state()).encode(), "application/json")
                elif self.path in ("/", "/index.html"):
                    self._send(PAGE.encode(), "text/html; charset=utf-8")
                elif self.path == "/healthz":
                    self._send(b"ok", "text/plain")
                else:
                    self.send_error(404)
        return H

    def start(self):
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()
        log("Dashboard: http://%s:%d  (state at /state.json)" % (self.host, self.port))
        return self

    def stop(self):
        try:
            self.httpd.shutdown()
        except Exception:  # noqa
            pass


def main(argv):
    ap = argparse.ArgumentParser(description="vEPC/EPC web dashboard")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    a = ap.parse_args(argv)
    d = Dashboard(host=a.host, port=a.port)
    d.start()
    try:
        while True:
            threading.Event().wait(1)
    except KeyboardInterrupt:
        d.stop()


if __name__ == "__main__":
    main(sys.argv[1:])
