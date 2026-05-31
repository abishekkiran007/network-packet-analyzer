import json, sys, os, time, threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from core.analyzer import PacketAnalyzer
from core.simulator import SimulatedCapture

analyzer = PacketAnalyzer(max_packets=500)
sim = SimulatedCapture(analyzer, pps=6)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def do_GET(self):
        path = urlparse(self.path).path
        if   path == "/":            self._html()
        elif path == "/api/stats":   self._json(analyzer.get_stats_snapshot())
        elif path == "/api/packets": self._json(analyzer.get_recent_packets(40))
        else:
            self.send_response(404); self.end_headers()

    def _json(self, data):
        body = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type","application/json")
        self.send_header("Access-Control-Allow-Origin","*")
        self.end_headers(); self.wfile.write(body)

    def _html(self):
        body = DASHBOARD_HTML.encode()
        self.send_response(200)
        self.send_header("Content-Type","text/html; charset=utf-8")
        self.end_headers(); self.wfile.write(body)


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Network Packet Analyzer — Abishek D</title>
<style>
:root{--bg:#0a0e1a;--panel:#0f1629;--border:#1e2d4a;--accent:#00d4ff;--green:#00ff88;
--yellow:#ffcc00;--purple:#a78bfa;--text:#e2e8f0;--muted:#64748b;
--tcp:#3b82f6;--udp:#10b981;--icmp:#f59e0b;--other:#6b7280}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:'JetBrains Mono','Fira Code',monospace;font-size:13px}
header{background:var(--panel);border-bottom:1px solid var(--border);padding:14px 24px;
  display:flex;align-items:center;justify-content:space-between}
.logo-dot{width:10px;height:10px;border-radius:50%;background:var(--green);
  box-shadow:0 0 8px var(--green);animation:pulse 1.5s infinite;margin-right:10px;display:inline-block}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.logo-text{font-size:15px;font-weight:700;color:var(--accent);letter-spacing:1px}
.logo-sub{font-size:11px;color:var(--muted);margin-top:1px}
.badge{padding:4px 12px;border-radius:20px;font-size:11px}
.badge-green{background:#0d2a1a;border:1px solid var(--green);color:var(--green)}
.badge-blue{background:#0a1a2a;border:1px solid var(--accent);color:var(--accent)}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;padding:16px 24px 0}
.card{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:16px;position:relative;overflow:hidden}
.card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px}
.card.blue::before{background:var(--tcp)}.card.green::before{background:var(--green)}
.card.yellow::before{background:var(--yellow)}.card.purple::before{background:var(--purple)}
.card-label{font-size:10px;color:var(--muted);letter-spacing:1px;text-transform:uppercase;margin-bottom:8px}
.card-val{font-size:28px;font-weight:700;line-height:1}
.card-val.blue{color:var(--tcp)}.card-val.green{color:var(--green)}
.card-val.yellow{color:var(--yellow)}.card-val.purple{color:var(--purple)}
.card-sub{font-size:11px;color:var(--muted);margin-top:6px}
.proto-wrap{padding:12px 24px 0}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:10px;overflow:hidden}
.panel-hdr{padding:10px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
.panel-title{font-size:11px;font-weight:600;color:var(--accent);letter-spacing:1px;text-transform:uppercase}
.proto-segs{display:flex;gap:14px;font-size:11px}
.proto-seg{display:flex;align-items:center;gap:5px}
.proto-dot{width:8px;height:8px;border-radius:2px}
.pbar-wrap{height:8px;background:#1a2540;border-radius:4px;margin:10px 16px;display:flex;overflow:hidden}
.pbar-seg{height:100%;transition:width .6s ease}
.main{display:grid;grid-template-columns:1fr 300px;gap:12px;padding:12px 24px}
.tbl-wrap{overflow:auto;max-height:380px}
table{width:100%;border-collapse:collapse}
thead th{position:sticky;top:0;background:#0c1220;padding:8px 12px;text-align:left;
  font-size:10px;color:var(--muted);letter-spacing:1px;text-transform:uppercase;border-bottom:1px solid var(--border)}
tbody tr{border-bottom:1px solid #111827;transition:background .15s}
tbody tr:hover{background:#111827}
tbody td{padding:7px 12px;font-size:12px}
.pbadge{display:inline-block;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700}
.pbadge-TCP{background:#1d3461;color:var(--tcp)}.pbadge-UDP{background:#0d2a1a;color:var(--udp)}
.pbadge-ICMP{background:#2d1a0a;color:var(--icmp)}.pbadge-OTHER{background:#1a1a2e;color:var(--other)}
.ftag{font-size:10px;color:var(--yellow);background:#2a2000;padding:1px 5px;border-radius:3px}
.side{display:flex;flex-direction:column;gap:12px}
.ip-row{display:flex;align-items:center;padding:6px 14px;gap:8px}
.ip-row:hover{background:#111827}
.ip-addr{color:var(--text);font-size:12px;min-width:130px}
.ip-bar-bg{flex:1;height:4px;background:#1a2540;border-radius:2px}
.ip-bar{height:100%;border-radius:2px;background:var(--accent);transition:width .5s}
.ip-cnt{color:var(--muted);font-size:11px;min-width:22px;text-align:right}
.port-row{margin:8px 16px}
.port-hdr{display:flex;justify-content:space-between;margin-bottom:4px;font-size:11px}
.port-name{color:var(--text)}.port-cnt{color:var(--muted)}
.port-bg{height:5px;background:#1a2540;border-radius:3px}
.port-fill{height:100%;border-radius:3px;background:var(--purple);transition:width .5s}
footer{text-align:center;padding:10px;color:var(--muted);font-size:11px;border-top:1px solid var(--border)}
</style>
</head>
<body>
<header>
  <div style="display:flex;align-items:center">
    <div class="logo-dot"></div>
    <div>
      <div class="logo-text">NETWORK PACKET ANALYZER</div>
      <div class="logo-sub">by Abishek D &nbsp;·&nbsp; Month 1 Project &nbsp;·&nbsp; github.com/abishekkiran007</div>
    </div>
  </div>
  <div style="display:flex;align-items:center;gap:12px">
    <span class="badge badge-green">● LIVE</span>
    <span class="badge badge-blue" id="pps-badge">0.0 pps</span>
    <span style="color:var(--muted);font-size:11px" id="elapsed">0s</span>
  </div>
</header>

<div class="grid">
  <div class="card blue"><div class="card-label">Total Packets</div><div class="card-val blue" id="c-pkts">0</div><div class="card-sub">captured</div></div>
  <div class="card green"><div class="card-label">Total Bytes</div><div class="card-val green" id="c-bytes">0</div><div class="card-sub">transferred</div></div>
  <div class="card yellow"><div class="card-label">TCP / UDP / ICMP</div><div class="card-val yellow" id="c-protos">—</div><div class="card-sub">protocol split %</div></div>
  <div class="card purple"><div class="card-label">Top Service</div><div class="card-val purple" id="c-topsvc">—</div><div class="card-sub">by traffic</div></div>
</div>

<div class="proto-wrap">
  <div class="panel">
    <div class="panel-hdr">
      <span class="panel-title">Protocol Distribution</span>
      <div class="proto-segs">
        <div class="proto-seg"><div class="proto-dot" style="background:var(--tcp)"></div>TCP <b id="pt-tcp" style="color:var(--tcp)">0%</b></div>
        <div class="proto-seg"><div class="proto-dot" style="background:var(--udp)"></div>UDP <b id="pt-udp" style="color:var(--udp)">0%</b></div>
        <div class="proto-seg"><div class="proto-dot" style="background:var(--icmp)"></div>ICMP <b id="pt-icmp" style="color:var(--icmp)">0%</b></div>
        <div class="proto-seg"><div class="proto-dot" style="background:var(--other)"></div>Other <b id="pt-other" style="color:var(--other)">0%</b></div>
      </div>
    </div>
    <div class="pbar-wrap">
      <div class="pbar-seg" id="pb-tcp"   style="background:var(--tcp);width:0%"></div>
      <div class="pbar-seg" id="pb-udp"   style="background:var(--udp);width:0%"></div>
      <div class="pbar-seg" id="pb-icmp"  style="background:var(--icmp);width:0%"></div>
      <div class="pbar-seg" id="pb-other" style="background:var(--other);width:0%"></div>
    </div>
  </div>
</div>

<div class="main">
  <div class="panel">
    <div class="panel-hdr">
      <span class="panel-title">Live Packet Stream</span>
      <span style="color:var(--muted);font-size:11px" id="pkt-lbl">0 packets</span>
    </div>
    <div class="tbl-wrap">
      <table>
        <thead><tr><th>Time</th><th>Proto</th><th>Flags</th><th>Source</th><th>Destination</th><th>Len</th><th>TTL</th></tr></thead>
        <tbody id="tbody"></tbody>
      </table>
    </div>
  </div>

  <div class="side">
    <div class="panel">
      <div class="panel-hdr"><span class="panel-title">Top Sources</span></div>
      <div id="src-ips" style="padding:6px 0"></div>
    </div>
    <div class="panel">
      <div class="panel-hdr"><span class="panel-title">Top Destinations</span></div>
      <div id="dst-ips" style="padding:6px 0"></div>
    </div>
    <div class="panel">
      <div class="panel-hdr"><span class="panel-title">Top Ports / Services</span></div>
      <div id="ports" style="padding:8px 0"></div>
    </div>
  </div>
</div>

<footer>Network Packet Analyzer &nbsp;|&nbsp; Abishek D &nbsp;|&nbsp; Month 1 / 12</footer>

<script>
const fmt = n => n>=1e6?(n/1e6).toFixed(1)+'M':n>=1e3?(n/1e3).toFixed(1)+'K':String(n);

function ipList(id, data) {
  const max = Math.max(...Object.values(data),1);
  document.getElementById(id).innerHTML = Object.entries(data).map(([ip,cnt])=>`
    <div class="ip-row">
      <span class="ip-addr">${ip}</span>
      <div class="ip-bar-bg"><div class="ip-bar" style="width:${Math.round(cnt/max*100)}%"></div></div>
      <span class="ip-cnt">${cnt}</span>
    </div>`).join('');
}

function portList(data) {
  const max = Math.max(...Object.values(data),1);
  document.getElementById('ports').innerHTML = Object.entries(data).map(([s,c])=>`
    <div class="port-row">
      <div class="port-hdr"><span class="port-name">${s}</span><span class="port-cnt">${c}</span></div>
      <div class="port-bg"><div class="port-fill" style="width:${Math.round(c/max*100)}%"></div></div>
    </div>`).join('');
}

function renderPackets(pkts) {
  document.getElementById('tbody').innerHTML = pkts.map(p=>{
    const sp = p.src_port?`<span style="color:var(--muted)">:${p.src_port}</span>`:'';
    const dp = p.dst_port?`<span style="color:var(--muted)">:${p.dst_port}</span>`:'';
    const bc = ['TCP','UDP','ICMP'].includes(p.protocol)?p.protocol:'OTHER';
    const fl = p.flags?`<span class="ftag">${p.flags}</span>`:`<span style="color:#2a3a4a">—</span>`;
    return `<tr>
      <td style="color:var(--muted)">${p.timestamp}</td>
      <td><span class="pbadge pbadge-${bc}">${p.protocol}</span></td>
      <td>${fl}</td>
      <td>${p.src_ip}${sp}</td>
      <td>${p.dst_ip}${dp}</td>
      <td style="color:var(--muted)">${p.length}</td>
      <td style="color:var(--muted)">${p.ttl}</td>
    </tr>`;
  }).join('');
}

async function tick() {
  try {
    const [sr,pr] = await Promise.all([fetch('/api/stats'),fetch('/api/packets')]);
    const s=await sr.json(), pkts=await pr.json(), pb=s.protocol_breakdown;
    document.getElementById('c-pkts').textContent   = fmt(s.total_packets);
    document.getElementById('c-bytes').textContent  = fmt(s.total_bytes);
    document.getElementById('c-protos').textContent = `${pb.TCP}/${pb.UDP}/${pb.ICMP}`;
    document.getElementById('c-topsvc').textContent = Object.keys(s.top_ports)[0]||'—';
    document.getElementById('pps-badge').textContent= `${s.pps} pps`;
    document.getElementById('elapsed').textContent  = `${s.elapsed_seconds}s`;
    document.getElementById('pkt-lbl').textContent  = `${s.total_packets} packets`;
    ['tcp','udp','icmp','other'].forEach(k=>{
      const v = pb[k.charAt(0).toUpperCase()+k.slice(1)];
      document.getElementById(`pt-${k}`).textContent = v+'%';
      document.getElementById(`pb-${k}`).style.width = v+'%';
    });
    ipList('src-ips', s.top_src_ips);
    ipList('dst-ips', s.top_dst_ips);
    portList(s.top_ports);
    renderPackets(pkts);
  } catch(e){console.error(e);}
}
tick(); setInterval(tick,1500);
</script>
</body>
</html>"""


def main():
    sim.start()
    server = HTTPServer(("127.0.0.1", 5000), Handler)
    print("\n  +------------------------------------------+")
    print("  |   Network Packet Analyzer Dashboard      |")
    print("  |   Open --> http://127.0.0.1:5000         |")
    print("  |   Ctrl+C to stop                         |")
    print("  +------------------------------------------+\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sim.stop()
        print("\n  Stopped.")


if __name__ == "__main__":
    main()