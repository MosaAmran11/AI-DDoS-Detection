"""
Deprecated shim: `dashboard_app_fixed.py` was a generated replacement.
Please use `dashboard_app.py` as the canonical dashboard entrypoint.

This module re-exports the `app` object from `dashboard_app` when available.
"""
try:
    from dashboard_app import app  # type: ignore
    print('dashboard_app_fixed: forwarding to dashboard_app.app')
except Exception:
    # If dashboard_app is missing, create a minimal placeholder app that shows a helpful message
    from flask import Flask
    app = Flask(__name__)
    @app.route('/')
    def info():
        return 'Deprecated file. Run dashboard_app.py instead.'

HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI-Driven DDoS SIEM</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@300;400;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-body: #3B4962;
            --bg-card: #1e293b;
            --text-main: #f1f5f9;
            --text-muted: #94a3b8;
            --accent-blue: #38bdf8;
            --accent-red: #f97373;
            --accent-green: #22c55e;
            --border-color: #334155;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { background: var(--bg-body); color: var(--text-main); font-family: 'Inter', sans-serif; height: 100vh; display: flex; flex-direction: column; overflow: hidden; }
        header { height: 60px; background: var(--bg-card); border-bottom: 1px solid var(--border-color); display: flex; align-items: center; justify-content: space-between; padding: 0 20px; flex-shrink: 0; }
        .brand { font-family: 'JetBrains Mono', monospace; font-weight: 700; font-size: 1.1rem; color: var(--accent-blue); display: flex; align-items: center; gap: 10px; }
        .status-indicator { padding: 6px 12px; border-radius: 4px; font-weight: 600; font-size: 0.9rem; letter-spacing: 0.5px; transition: all 0.3s ease; }
        .status-safe { background: rgba(34, 197, 94, 0.12); color: var(--accent-green); border: 1px solid rgba(34,197,94,0.18); }
        .status-danger { background: rgba(239, 68, 68, 0.12); color: var(--accent-red); border: 1px solid rgba(239,68,68,0.18); animation: pulse 1.5s infinite; }
        .btn-export { background: var(--accent-blue); color: #0f172a; border: none; padding: 8px 14px; border-radius: 6px; font-weight: 600; cursor: pointer; display: flex; align-items: center; gap: 8px; }
        .dashboard-grid { display: grid; grid-template-columns: 3fr 1fr; grid-template-rows: auto 1fr 1fr; gap: 15px; padding: 15px; height: calc(100vh - 60px); overflow-y: auto; }
        .card { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; padding: 15px; display: flex; flex-direction: column; position: relative; }
        .card-header { font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); margin-bottom: 10px; display: flex; justify-content: space-between; }
        .kpi-row { grid-column: span 2; display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; min-height: 80px; }
        .kpi-value { font-size: 1.6rem; font-weight: 700; margin-top: auto; font-family: 'JetBrains Mono', monospace; }
        .chart-section { grid-column: 1 / 2; grid-row: 2 / 4; min-height: 300px; }
        .chart-container-wrapper { position: relative; flex-grow: 1; width: 100%; height: 100%; }
        #trafficChart { width: 100% !important; height: 100% !important; display: block; }
        .ai-sidebar { grid-column: 2 / 3; grid-row: 2 / 3; overflow-y: auto; }
        .feature-row { margin-bottom: 12px; }
        .feature-label { display: flex; justify-content: space-between; font-size: 0.8rem; margin-bottom: 4px; }
        .progress-bg { background: #334155; height: 6px; border-radius: 3px; overflow: hidden; }
        .progress-fill { height: 100%; background: var(--accent-blue); transition: width 0.5s ease; }
        .logs-section { grid-column: 2 / 3; grid-row: 3 / 4; overflow: hidden; display: flex; flex-direction: column; }
        .table-container { overflow-y: auto; flex-grow: 1; }
        table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
        th { text-align: left; color: var(--text-muted); padding: 8px; position: sticky; top: 0; background: var(--bg-card); border-bottom: 1px solid var(--border-color); }
        td { padding: 6px 8px; border-bottom: 1px solid #334155; font-family: 'JetBrains Mono', monospace; }
        .log-alert { color: var(--accent-red); }
        @keyframes pulse { 0% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.4); } 70% { box-shadow: 0 0 0 10px rgba(239, 68, 68, 0); } 100% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); } }
        @media (max-width: 900px) { .dashboard-grid { grid-template-columns: 1fr; grid-template-rows: auto auto 1fr auto; } .chart-section { grid-column: 1 / -1; grid-row: 2 / 3; } .ai-sidebar { grid-column: 1 / -1; grid-row: 3 / 4; } .logs-section { grid-column: 1 / -1; grid-row: 4 / 5; } }
    </style>
</head>
<body>

    <header>
        <div class="brand">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
            SHIELD AI <span style="font-size: 0.8em; opacity: 0.7;">| DDoS Monitor</span>
        </div>
        <div style="display:flex;align-items:center;gap:12px;">
            <div id="now-clock" style="color:#9aa4b2;font-size:13px">-</div>
            <div id="statusBanner" class="status-indicator status-safe">SECURE</div>
            <button class="btn-export" onclick="exportData()">Export PCAP Log</button>
        </div>
    </header>

    <div class="dashboard-grid">
        <div class="kpi-row">
            <div class="card">
                <div class="card-header">Threat Score</div>
                <div class="kpi-value" id="scoreVal">0.00%</div>
            </div>
            <div class="card">
                <div class="card-header">Packets / Sec</div>
                <div class="kpi-value" id="ppsVal" style="color: var(--accent-green);">0</div>
            </div>
            <div class="card">
                <div class="card-header">Bytes / Sec</div>
                <div class="kpi-value" id="bpsVal">0</div>
            </div>
            <div class="card">
                <div class="card-header">Active Flows</div>
                <div class="kpi-value" id="flowsVal">--</div>
            </div>
        </div>

        <div class="card chart-section">
            <div class="card-header"><span>Real-Time Traffic Analysis</span><span style="font-size:10px;opacity:0.5;">LIVE FEED</span></div>
            <div class="chart-container-wrapper"><canvas id="trafficChart"></canvas></div>
        </div>

        <div class="card ai-sidebar">
            <div class="card-header">Feature Contribution</div>
            <div id="featuresList"><div style="text-align:center;color:#6b7280;margin-top:40px">Waiting for data...</div></div>
        </div>

        <div class="card logs-section" style="max-height:260px;display:flex;flex-direction:column">
            <div class="card-header">Detection Events</div>
            <div class="table-container" style="flex:1;overflow-y:auto">
                <table id="logsTable"><thead><tr><th>Time</th><th>Type</th><th>Score</th></tr></thead><tbody id="logsBody"></tbody></table>
            </div>
        </div>
    </div>

<script>
    const FEATURE_ORDER = __FEATURE_ORDER__;
    // build features panel
    const featuresDiv = document.getElementById('featuresList');
    function buildFeaturesPlaceholder(){ featuresDiv.innerHTML = '<div style="text-align:center;color:#6b7280;margin-top:40px">Waiting for data...</div>'; }
    buildFeaturesPlaceholder();

    // traffic chart
    const ctx = document.getElementById('trafficChart').getContext('2d');
    const gradPackets = ctx.createLinearGradient(0,0,0,400);
    gradPackets.addColorStop(0,'rgba(34, 197, 94, 0.12)');
    gradPackets.addColorStop(1,'rgba(34, 197, 94, 0.02)');
    const gradBytes = ctx.createLinearGradient(0,0,0,400);
    gradBytes.addColorStop(0,'rgba(56, 189, 248, 0.12)');
    gradBytes.addColorStop(1,'rgba(56, 189, 248, 0.02)');

    const trafficChart = new Chart(ctx, {
        type: 'line',
        data: { labels: Array(60).fill(''), datasets: [
            { label: 'Packets', data: Array(60).fill(0), borderColor: '#22c55e', backgroundColor: gradPackets, fill: true, tension: 0.3, yAxisID: 'y' },
            { label: 'Bytes (Scaled)', data: Array(60).fill(0), borderColor: '#38bdf8', borderDash: [5,5], tension: 0.3, yAxisID: 'y1' }
        ]},
        options: { responsive: true, maintainAspectRatio: false, interaction: { mode: 'index', intersect: false }, plugins: { legend: { position: 'top', labels: { color: '#94a3b8' } } }, scales: { x: { display: false }, y: { type: 'linear', display: true, position: 'left', grid: { color: '#334155' }, ticks: { color: '#94a3b8' } }, y1: { type: 'linear', display: true, position: 'right', grid: { drawOnChartArea: false }, ticks: { color: '#94a3b8' } } } }
    });
    window.trafficChart = trafficChart;

    let globalAlerts = [];

    function updateDashboard(){
        fetch('/api/state').then(r=>r.json()).then(data=>{
            const scorePct = (data.last_score * 100).toFixed(2);
            document.getElementById('scoreVal').innerText = scorePct + "%";
            document.getElementById('scoreVal').style.color = data.last_score > 0.5 ? '#f97373' : '#f1f5f9';

            const banner = document.getElementById('statusBanner');
            if(data.is_attack){ banner.innerText = 'ATTACK DETECTED'; banner.className = 'status-indicator status-danger'; }
            else { banner.innerText = 'SECURE'; banner.className = 'status-indicator status-safe'; }

            // traffic
            if(data.traffic_history && data.traffic_history.length > 0){
                const latest = data.traffic_history[data.traffic_history.length - 1];
                document.getElementById('ppsVal').innerText = latest.packets;
                let bytesVal = latest.bytes || 0; let unit = 'B';
                if(bytesVal > 1024){ bytesVal /= 1024; unit = 'KB'; }
                if(bytesVal > 1024){ bytesVal /= 1024; unit = 'MB'; }
                document.getElementById('bpsVal').innerText = bytesVal.toFixed(1) + ' ' + unit;

                trafficChart.data.datasets[0].data = data.traffic_history.map(d=>d.packets);
                trafficChart.data.datasets[1].data = data.traffic_history.map(d=>d.bytes/1000);
                trafficChart.update('none');
            }

            // features panel
            const displayKeys = ['tcp_count','udp_count','icmp_count','avg_pkt_size','duration_sec'];
            let html='';
            displayKeys.forEach(k=>{
                const val = (data.last_features && data.last_features[k]) ? data.last_features[k] : 0;
                let max = k.includes('count') ? 1000 : 1500; let pct = Math.min((val/max)*100,100);
                html += `<div class="feature-row"><div class="feature-label"><span>${k.toUpperCase().replace('_',' ')}</span><span>${Number(val).toFixed(1)}</span></div><div class="progress-bg"><div class="progress-fill" style="width: ${pct}%"></div></div></div>`;
            });
            featuresDiv.innerHTML = html || '<div style="text-align:center;color:#6b7280;margin-top:40px">No feature data</div>';

            // logs
            const logsBody = document.getElementById('logsBody');
            logsBody.innerHTML = '';
            globalAlerts = data.alerts || [];
            (data.alerts || []).slice().reverse().forEach(a=>{
                const ts = a.timestamp || new Date().toLocaleTimeString();
                const row = `<tr><td>${ts}</td><td class="log-alert">${a.event_type || 'DDoS'}</td><td>${(a.score||0).toFixed(2)}</td></tr>`;
                logsBody.innerHTML += row;
            });
        }).catch(err=>{ /* backend maybe not ready */ });
    }

    function sanitizeFilename(name){ return name.replace(/[:]/g,'-'); }
    function exportData(){
        const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(globalAlerts, null, 2));
        const a = document.createElement('a');
        a.setAttribute('href', dataStr);
        a.setAttribute('download', 'attack_report_' + sanitizeFilename(new Date().toISOString()) + '.json');
        document.body.appendChild(a); a.click(); a.remove();
        alert('Report Downloaded!');
    }

    window.addEventListener('resize', () => { if(window.trafficChart) window.trafficChart.resize(); });
    // Clock sync: update header clock every second (client/browser time)
    function updateNowClock(){ try{ const el = document.getElementById('now-clock'); if(el) el.innerText = new Date().toLocaleTimeString(); }catch(e){} }
    updateNowClock(); setInterval(updateNowClock, 1000);
    setInterval(updateDashboard, 1000);
    updateDashboard();
</script>
</body>
</html>
'''

HTML = HTML.replace('__FEATURE_ORDER__', json.dumps(FEATURE_ORDER))

@app.route('/')
def index():
    return render_template_string(HTML)

@app.route('/api/update', methods=['POST'])
def api_update():
    data = request.json or {}
    score = float(data.get('score',0))
    attack = bool(data.get('attack',False))
    features = data.get('features',{}) or {}
    STATE['last_score']=score
    STATE['is_attack']=attack
    STATE['last_update']=time.time()
    if isinstance(features,dict):
        for k in FEATURE_ORDER:
            STATE['last_features'][k]=float(features.get(k,0))
        STATE['traffic_history'].append({'packets':float(features.get('packet_count',0)),'bytes':float(features.get('byte_count',0)),'timestamp':time.time()})
    if attack:
        STATE['alerts'].append({'timestamp':time.strftime('%Y-%m-%d %H:%M:%S'),'event_type':'DDoS','score':score,'metadata':features})
        STATE['alerts']=STATE['alerts'][-1000:]
    return jsonify(success=True)

@app.route('/api/state')
def api_state():
    return jsonify({'last_score':STATE['last_score'],'is_attack':STATE['is_attack'],'last_update':STATE['last_update'],'last_features':STATE['last_features'],'feature_order':STATE['feature_order'],'traffic_history':list(STATE['traffic_history']),'alerts':STATE['alerts']})

if __name__=='__main__':
    app.run(host='0.0.0.0',port=5000,debug=False)
