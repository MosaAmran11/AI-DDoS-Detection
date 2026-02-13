from flask import Flask, jsonify, render_template_string, request
import time
from collections import deque
from pathlib import Path
import json

app = Flask(__name__)

# Load feature order
FEATURE_FILE = Path(__file__).parent / 'feature_columns.json'
try:
    FEATURE_ORDER = json.loads(FEATURE_FILE.read_text())
except Exception:
    FEATURE_ORDER = [
        "packet_count","byte_count","avg_pkt_size","std_pkt_size","duration_sec",
        "unique_src_ips","unique_dst_ips","tcp_count","udp_count","icmp_count"
    ]

# Shared state
STATE = {
    'last_score': 0.0,
    'is_attack': False,
    'last_update': 0,
    'last_features': {k: 0 for k in FEATURE_ORDER},
    'feature_order': FEATURE_ORDER,
    'traffic_history': deque(maxlen=60),
    'alerts': [],
}

HTML_PAGE = """
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>SIEM - DDoS Detection</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
      body{background:#0b0f14;color:#e6eef6;font-family:Inter,Segoe UI,Arial;margin:0}
      .container{display:grid;max-width:1200px;margin:24px auto;grid-template-columns:300px 1fr;grid-template-rows:72px 1fr;gap:18px;min-height:calc(100vh - 48px);padding:20px;box-sizing:border-box}
      .card{background:#0f1720;border-radius:10px;padding:20px;box-shadow:0 2px 10px rgba(0,0,0,0.45)}
      #trafficChart{height:340px;width:100%}
      @media (max-width:1100px){.container{grid-template-columns:1fr;padding:12px}#trafficChart{height:260px}}
    </style>
  </head>
  <body>
    <div class="container">
      <div class="card" id="header" style="grid-column:1/3;display:flex;align-items:center;justify-content:space-between">
        <div><strong style="font-size:18px">SIEM — AI DDoS Detection</strong><div style="color:#9aa4b2;font-size:12px">Real-time insights</div></div>
        <div style="display:flex;align-items:center;gap:12px">
          <div id="now-clock" style="color:#9aa4b2;font-size:13px">-</div>
          <div id="statusBanner" style="padding:6px 12px;border-radius:6px;background:#064e3b;color:#a7f3d0;font-weight:700">SECURE</div>
          <div id="last-update" style="color:#9aa4b2">-</div>
        </div>
      </div>
      <aside class="card" id="sidebar"><h3 style="margin-top:0">AI Insights</h3><div id="feature-list"></div></aside>
      <main>
        <div class="card"><canvas id="trafficChart"></canvas></div>
        <div style="display:grid;grid-template-columns:1fr 420px;gap:16px;margin-top:16px">
          <div class="card" style="max-height:260px;display:flex;flex-direction:column">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
              <h3 style="margin:0">SIEM Log</h3>
              <div><button id="scrollBtn" style="font-size:12px;padding:6px 8px;border-radius:6px;border:1px solid #2b3340;background:#0f1720;color:#cfe6ff;cursor:pointer">Jump to latest</button></div>
            </div>
            <div id="alerts-container" style="flex:1;overflow-y:auto;padding-right:6px">
              <table id="alerts-table" style="width:100%"><thead><tr><th style="text-align:left">Timestamp</th><th style="text-align:left">Type</th><th style="text-align:left">Score</th></tr></thead><tbody></tbody></table>
            </div>
          </div>
          <div class="card" style="max-height:260px;display:flex;flex-direction:column">
            <h3 style="margin-top:0">Last Features</h3>
            <div id="features-container" style="flex:1;overflow-y:auto;padding:8px;background:transparent">
              <table id="features-table" style="width:100%"><tbody></tbody></table>
            </div>
          </div>
        </div>
      </main>
    </div>
  <script>
    const FEATURE_ORDER = __FEATURE_ORDER__;
    const featureList = document.getElementById('feature-list');
    FEATURE_ORDER.forEach(k=>{const d=document.createElement('div');d.style.marginBottom='10px';d.innerHTML=`<div style="font-size:13px;color:#cfe6ff">${k}</div><div class="bar" id="bar-${k}"><i style="display:block;width:0;height:12px;background:#58a6ff;border-radius:6px"></i></div>`;featureList.appendChild(d)});
    const ctx=document.getElementById('trafficChart').getContext('2d');
    const gradPackets = ctx.createLinearGradient(0,0,0,400);gradPackets.addColorStop(0,'rgba(88,166,255,0.45)');gradPackets.addColorStop(1,'rgba(88,166,255,0.03)');
    const gradBytes = ctx.createLinearGradient(0,0,0,400);gradBytes.addColorStop(0,'rgba(249,115,115,0.35)');gradBytes.addColorStop(1,'rgba(249,115,115,0.02)');
      // Mixed chart: Packets (line), Moving Average (thin line), Volume (bytes) as bars (y1)    
      // Clock sync: update header clock every second (client/browser time)
      function updateNowClock(){ try{ const el = document.getElementById('now-clock'); if(el) el.innerText = new Date().toLocaleTimeString(); }catch(e){} }
      updateNowClock(); setInterval(updateNowClock, 1000);
    const chart=new Chart(ctx,{type:'line',data:{labels:[],datasets:[
      {type:'line',label:'Packets/sec',data:[],borderColor:'#58a6ff',backgroundColor:gradPackets,tension:0.3,cubicInterpolationMode:'monotone',pointRadius:0,fill:true,borderWidth:2,yAxisID:'y'},
      {type:'line',label:'MA(5)',data:[],borderColor:'#94a3b8',backgroundColor:'rgba(148,163,184,0.08)',tension:0.2,pointRadius:0,fill:false,borderDash:[4,4],borderWidth:1,yAxisID:'y'},
      {type:'bar',label:'Bytes/sec',data:[],backgroundColor:'rgba(248,81,73,0.24)',borderColor:'rgba(248,81,73,0.6)',borderWidth:1,yAxisID:'y1'}
    ]},options:{responsive:true,maintainAspectRatio:false,interaction:{mode:'index',intersect:false},plugins:{legend:{display:true,position:'top',labels:{usePointStyle:true}}},scales:{y:{beginAtZero:true},y1:{position:'right',beginAtZero:true,grid:{drawOnChartArea:false}}},elements:{line:{cap:'round'}},spanGaps:true}});
    // Plugin: playhead arrow + vertical signal line at latest data point
    Chart.register({
      id: 'playhead',
      afterDraw: function(chart) {
        try {
          const ctx = chart.ctx;
          const len = chart.data.labels.length;
          if (!len) return;
          const meta = chart.getDatasetMeta(0);
          const point = meta.data[len-1];
          if (!point) return;
          const x = point.x;
          const y = point.y;
          const pressure = window.currentPressure || 0;
          const color = pressure>7.5 ? '#f97373' : (pressure>=5? '#f59e0b' : '#10b981');
          ctx.save();
          // vertical dashed playhead line
          ctx.strokeStyle = color;
          ctx.lineWidth = 1;
          ctx.setLineDash([6,4]);
          ctx.beginPath();
          ctx.moveTo(x, chart.chartArea.top);
          ctx.lineTo(x, chart.chartArea.bottom);
          ctx.stroke();
          ctx.setLineDash([]);
          // arrow triangle above the point
          const size = Math.max(8, Math.min(18, 8 + (pressure-5)));
          ctx.fillStyle = color;
          ctx.beginPath();
          ctx.moveTo(x, y - 6);
          ctx.lineTo(x - size/2, y - 6 - size);
          ctx.lineTo(x + size/2, y - 6 - size);
          ctx.closePath();
          ctx.fill();
          ctx.restore();
        } catch (e) {
          // swallow drawing errors to avoid breaking the chart
        }
      }
    });
    function setBar(k,v,atk){const b=document.querySelector('#bar-'+k+' i');if(!b) return;const pct = Math.min(100, Math.round(v));b.style.width = pct + '%';b.style.background = atk ? '#f97373' : '#58a6ff';}
    function addAlert(a){const t=document.querySelector('#alerts-table tbody');const tr=document.createElement('tr');tr.innerHTML = `<td>${a.timestamp}</td><td>${a.event_type}</td><td>${(a.score||0).toFixed(4)}</td>`;t.prepend(tr);while(t.children.length > 200) t.removeChild(t.lastChild);}
    function refresh(){fetch('/api/state').then(r=>r.json()).then(d=>{
      document.getElementById('last-update').innerText = new Date((d.last_update||0)*1000).toLocaleTimeString();
      const atk = !!d.is_attack;
      // Compute a simple pressure metric (0-10) from last_score (0.0-1.0 => 0-10)
      const pressure = Math.min(10, Math.round((d.last_score || 0) * 10 * 10)/10);
      // Thresholds: <5 green (normal), 5-7.5 yellow (medium), >7.5 red (high)
      let colorLine = '#10b981'; // green
      let bannerText = 'SECURE';
      if (pressure >= 5 && pressure <= 7.5) { colorLine = '#f59e0b'; bannerText = 'WARNING'; }
      if (pressure > 7.5) { colorLine = '#f97373'; bannerText = 'ATTACK'; }
      // Update status banner
      const sb = document.getElementById('statusBanner'); if (sb) { sb.innerText = bannerText; sb.style.background = (pressure>7.5? 'rgba(248,81,73,0.12)': pressure>=5? 'rgba(245,158,11,0.12)' : 'rgba(16,185,129,0.08)'); sb.style.color = (pressure>7.5? '#fff' : (pressure>=5? '#f59e0b' : '#10b981')); }

      // expose pressure for playhead plugin
      window.currentPressure = pressure;
      FEATURE_ORDER.forEach(k=> setBar(k, d.last_features[k] || 0, atk));
      // update features table if present (avoid referencing missing #features element)
      const featuresTbody = document.querySelector('#features-table tbody');
      if (featuresTbody) {
        featuresTbody.innerHTML = '';
        FEATURE_ORDER.forEach(k=>{
          const v = (d.last_features && d.last_features[k]) ? Number(d.last_features[k]) : 0;
          const display = (Math.abs(v) >= 1000) ? v.toFixed(0) : v.toFixed(2);
          featuresTbody.innerHTML += `<tr><td style="padding:6px 8px;color:#cfe6ff;font-weight:600">${k}</td><td style="padding:6px 8px;text-align:right">${display}</td></tr>`;
        });
      }
      const history = d.traffic_history || [];
      const labels = history.map(h => new Date((h.timestamp||0)*1000).toLocaleTimeString());
      const packets = history.map(h => h.packets || 0);
      const bytes = history.map(h => h.bytes || 0);
      // compute simple moving average (window 5)
      const ma = [];
      const w = 5;
      for (let i=0;i<packets.length;i++){
        let start = Math.max(0,i-w+1);
        let sum=0;let cnt=0;for(let j=start;j<=i;j++){sum+=packets[j];cnt++;}
        ma.push(cnt?sum/cnt:0);
      }
      // Heartbeat/spike: if pressure is above threshold, exaggerate most recent packets point briefly
      if (pressure > 5 && packets.length){
        packets[packets.length-1] = packets[packets.length-1] * (1 + (pressure-5)/5); // scale spike
      }
      chart.data.labels = labels;
      chart.data.datasets[0].data = packets;
      chart.data.datasets[1].data = ma;
      chart.data.datasets[2].data = bytes;
      // Update colors dynamically
      chart.data.datasets[0].borderColor = colorLine;
      chart.data.datasets[0].backgroundColor = colorLine === '#10b981' ? gradPackets : (colorLine === '#f59e0b' ? 'rgba(245,158,11,0.18)' : 'rgba(249,115,115,0.12)');
      chart.data.datasets[1].borderColor = pressure > 7.5 ? '#f97373' : '#f97373';
      // Emphasize line width briefly on attack to create a pulse effect
      chart.data.datasets[0].borderWidth = pressure > 7.5 ? 4 : 2;
      chart.update();
      if(d.alerts) d.alerts.slice(-50).reverse().forEach(a=> addAlert(a));
    }).catch(()=>{});}setInterval(refresh,1000);refresh();
  </script>
  </body>
</html>
"""

HTML_PAGE = HTML_PAGE.replace('__FEATURE_ORDER__', json.dumps(FEATURE_ORDER))


@app.route('/')
def index():
    return render_template_string(HTML_PAGE)


@app.route('/api/update', methods=['POST'])
def api_update():
    data = request.json or {}
    if 'last_score' in data or 'last_features' in data:
        STATE['last_score'] = float(data.get('last_score', data.get('score', 0)))
        STATE['is_attack'] = bool(data.get('is_attack', data.get('attack', False)))
        STATE['last_update'] = time.time()
        features = data.get('last_features', data.get('features', {})) or {}
        if isinstance(features, dict):
            for k in FEATURE_ORDER:
                STATE['last_features'][k] = float(features.get(k, 0))
        for e in data.get('traffic_history', []) or []:
            try:
                STATE['traffic_history'].append({'packets': float(e.get('packets',0)), 'bytes': float(e.get('bytes',0)), 'timestamp': float(e.get('timestamp', time.time()))})
            except Exception:
                pass
        for a in data.get('alerts', []) or []:
            if isinstance(a, dict) and 'timestamp' in a:
                STATE['alerts'].append(a)
        STATE['alerts'] = STATE['alerts'][-1000:]
    else:
        score = float(data.get('score', 0))
        attack = bool(data.get('attack', False))
        features = data.get('features', {}) or {}
        STATE['last_score'] = score
        STATE['is_attack'] = attack
        STATE['last_update'] = time.time()
        if isinstance(features, dict):
            for k in FEATURE_ORDER:
                STATE['last_features'][k] = float(features.get(k, 0))
            STATE['traffic_history'].append({'packets': float(features.get('packet_count',0)), 'bytes': float(features.get('byte_count',0)), 'timestamp': time.time()})
        if attack:
            STATE['alerts'].append({'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'), 'event_type': 'DDoS', 'score': score, 'metadata': features})
            STATE['alerts'] = STATE['alerts'][-1000:]
    return jsonify(success=True)


@app.route('/api/state')
def api_state():
    return jsonify({'last_score': STATE['last_score'], 'is_attack': STATE['is_attack'], 'last_update': STATE['last_update'], 'last_features': STATE['last_features'], 'feature_order': STATE['feature_order'], 'traffic_history': list(STATE['traffic_history']), 'alerts': STATE['alerts']})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
