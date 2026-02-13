from flask import Flask, jsonify, render_template_string, request
import time
from collections import deque
from pathlib import Path
import json
import logging
import os

# Basic logging
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
logger = logging.getLogger('dashboard')

app = Flask(__name__)

# Load feature order from file if present
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

HTML_PAGE = r"""
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
            --bg-body: #0f172a;
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
        .status-danger { background: rgba(249, 115, 115, 0.12); color: var(--accent-red); border: 1px solid rgba(249,115,115,0.18); animation: pulse 1.5s infinite; }
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
        @keyframes pulse { 0% { box-shadow: 0 0 0 0 rgba(249, 115, 115, 0.4); } 70% { box-shadow: 0 0 0 10px rgba(249, 115, 115, 0); } 100% { box-shadow: 0 0 0 0 rgba(249, 115, 115, 0); } }
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

        <div class="card logs-section">
            <div class="card-header">Detection Events <button id="scrollBtn" style="float:right;padding:6px 8px;border-radius:6px;background:#0b1220;color:#9aa4b2;border:none">Jump to latest</button></div>
            <div id="alerts-container" class="table-container">
                <table id="logsTable"><thead><tr><th>Time</th><th>Type</th><th>Score</th></tr></thead><tbody id="logsBody"></tbody></table>
            </div>
        </div>
    </div>

<script>
    const FEATURE_ORDER = __FEATURE_ORDER__;
    const featuresDiv = document.getElementById('featuresList');
    function buildFeaturesPlaceholder(){ featuresDiv.innerHTML = '<div style="text-align:center;color:#6b7280;margin-top:40px">Waiting for data...</div>'; }
    buildFeaturesPlaceholder();

    // Chart
    const ctx = document.getElementById('trafficChart').getContext('2d');
    const gradPackets = ctx.createLinearGradient(0,0,0,400);
    gradPackets.addColorStop(0,'rgba(34, 197, 94, 0.12)');
    gradPackets.addColorStop(1,'rgba(34, 197, 94, 0.02)');
    const gradBytes = ctx.createLinearGradient(0,0,0,400);
    gradBytes.addColorStop(0,'rgba(56, 189, 248, 0.12)');
    gradBytes.addColorStop(1,'rgba(56, 189, 248, 0.02)');

    const trafficChart = new Chart(ctx, {
        type: 'line', data: { labels: Array(60).fill(''), datasets: [
            { label: 'Packets', data: Array(60).fill(0), borderColor: '#22c55e', backgroundColor: gradPackets, fill: true, tension: 0.3, yAxisID: 'y' },
            { label: 'Bytes (Scaled)', data: Array(60).fill(0), borderColor: '#38bdf8', borderDash: [5,5], tension: 0.3, yAxisID: 'y1' }
        ]}, options: { responsive: true, maintainAspectRatio: false, interaction: { mode: 'index', intersect: false }, plugins: { legend: { position: 'top', labels: { color: '#94a3b8' } } }, scales: { x: { display: false }, y: { type: 'linear', display: true, position: 'left', grid: { color: '#334155' }, ticks: { color: '#94a3b8' } }, y1: { type: 'linear', display: true, position: 'right', grid: { drawOnChartArea: false }, ticks: { color: '#94a3b8' } } } }
    });
    window.trafficChart = trafficChart;

    let globalAlerts = [];

    async function updateDashboard(){
        try{
            const r = await fetch('/api/state');
            const data = await r.json();
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

            // features table (ordered)
            const featuresTableBody = document.querySelector('#features-table tbody');
            if(!featuresTableBody){
                featuresDiv.innerHTML = `<table style="width:100%;border-collapse:collapse;font-size:0.85rem"><thead><tr><th style="text-align:left;color:#94a3b8">Feature</th><th style="text-align:right;color:#94a3b8">Value</th><th style="text-align:left;color:#94a3b8">Contribution</th></tr></thead><tbody id="features-table-body"></tbody></table>`;
            }
            const tbody = document.querySelector('#features-table-body');
            if(tbody){
                tbody.innerHTML = '';
                const order = data.feature_order && data.feature_order.length ? data.feature_order : FEATURE_ORDER;
                order.forEach(k=>{
                    const val = (data.last_features && data.last_features[k]) ? Number(data.last_features[k]) : 0;
                    const display = (Math.abs(val) >= 1000) ? Number(val).toFixed(0) : Number(val).toFixed(2);
                    const max = k.includes('count') ? 1000 : 1500;
                    const pct = Math.min(100, Math.round((Math.abs(val) / max) * 100));
                    const row = `<tr><td style="padding:6px 8px;color:#cfe6ff;font-weight:600">${k}</td><td style="padding:6px 8px;text-align:right">${display}</td><td style="padding:6px 8px;min-width:120px"><div style="background:#334155;height:8px;border-radius:4px;overflow:hidden"><div style="height:8px;background:#38bdf8;width:${pct}%"></div></div></td></tr>`;
                    tbody.innerHTML += row;
                });
            }

            // logs - preserve scroll unless user moved away
            const alertsContainer = document.getElementById('alerts-container');
            const wasAtBottom = (alertsContainer.scrollHeight - alertsContainer.clientHeight - alertsContainer.scrollTop) < 50;
            const logsBody = document.getElementById('logsBody');
            logsBody.innerHTML = '';
            globalAlerts = data.alerts || [];
            (data.alerts || []).slice().reverse().forEach(a=>{
                const ts = a.timestamp || new Date().toLocaleTimeString();
                const row = `<tr><td style="padding:6px 8px">${ts}</td><td class="log-alert" style="padding:6px 8px">${a.event_type || 'DDoS'}</td><td style="padding:6px 8px">${(a.score||0).toFixed(4)}</td></tr>`;
                logsBody.innerHTML += row;
            });
            if (wasAtBottom) alertsContainer.scrollTop = alertsContainer.scrollHeight;
        }catch(e){ /* backend maybe not ready */ }
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

    const scrollBtn = document.getElementById('scrollBtn');
    if (scrollBtn) {
        scrollBtn.addEventListener('click', () => {
            const c = document.getElementById('alerts-container'); if (c) c.scrollTop = c.scrollHeight;
        });
    }

    function updateNowClock(){ try{const el = document.getElementById('now-clock'); if(el) el.innerText = new Date().toLocaleTimeString();}catch(e){} }
    updateNowClock(); setInterval(updateNowClock, 1000);

    window.addEventListener('resize', () => { if(window.trafficChart) window.trafficChart.resize(); });
    setInterval(updateDashboard, 1000);
    updateDashboard();
</script>
</body>
</html>
"""

# Replace placeholder
HTML_PAGE = HTML_PAGE.replace('__FEATURE_ORDER__', json.dumps(FEATURE_ORDER))


@app.route('/')
def index():
    return render_template_string(HTML_PAGE)


@app.route('/api/update', methods=['POST'])
def api_update():
    payload = request.json or {}
    try:
        # structured payload
        if 'last_score' in payload or 'last_features' in payload:
            last_score = float(payload.get('last_score', payload.get('score', 0.0)))
            is_attack = bool(payload.get('is_attack', payload.get('attack', False)))
            last_features = payload.get('last_features', payload.get('features', {})) or {}
            traffic_history = payload.get('traffic_history', []) or []
            alerts = payload.get('alerts', []) or []

            STATE['last_score'] = last_score
            STATE['is_attack'] = is_attack
            STATE['last_update'] = time.time()
            if isinstance(last_features, dict):
                for k in STATE['feature_order']:
                    STATE['last_features'][k] = float(last_features.get(k, 0))

            for entry in traffic_history:
                if isinstance(entry, dict) and 'packets' in entry:
                    STATE['traffic_history'].append({'packets': float(entry.get('packets',0)), 'bytes': float(entry.get('bytes',0)), 'timestamp': float(entry.get('timestamp', time.time()))})

            for a in alerts:
                if isinstance(a, dict):
                    STATE['alerts'].append(a)
            STATE['alerts'] = STATE['alerts'][-1000:]

        else:
            # backward-compatible small payload
            score = float(payload.get('score', 0))
            attack = bool(payload.get('attack', False))
            features = payload.get('features', {}) or {}

            STATE['last_score'] = score
            STATE['is_attack'] = attack
            STATE['last_update'] = time.time()
            if isinstance(features, dict):
                for k in STATE['feature_order']:
                    STATE['last_features'][k] = float(features.get(k, 0))
                STATE['traffic_history'].append({'packets': float(features.get('packet_count',0)), 'bytes': float(features.get('byte_count',0)), 'timestamp': time.time()})
            if attack:
                STATE['alerts'].append({'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'), 'event_type': 'DDoS', 'score': score, 'metadata': features})
                STATE['alerts'] = STATE['alerts'][-1000:]

        return jsonify(success=True)
    except Exception as e:
        logger.exception('Error processing update')
        return jsonify(success=False, error=str(e)), 500


@app.route('/api/state')
def api_state():
    return jsonify({'last_score':STATE['last_score'],'is_attack':STATE['is_attack'],'last_update':STATE['last_update'],'last_features':STATE['last_features'],'feature_order':STATE['feature_order'],'traffic_history':list(STATE['traffic_history']),'alerts':STATE['alerts']})


@app.route('/health')
def health():
    return jsonify(status='ok')


if __name__ == '__main__':
    host = os.environ.get('DASH_HOST', '0.0.0.0')
    port = int(os.environ.get('DASH_PORT', '5000'))
    debug = os.environ.get('DASH_DEBUG', 'false').lower() in ('1','true','yes')
    logger.info(f'Starting dashboard on {host}:{port} debug={debug}')
    app.run(host=host, port=port, debug=debug)

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
            --bg-body: #0f172a;
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
        .status-danger { background: rgba(249, 115, 115, 0.12); color: var(--accent-red); border: 1px solid rgba(249,115,115,0.18); animation: pulse 1.5s infinite; }
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
        @keyframes pulse { 0% { box-shadow: 0 0 0 0 rgba(249, 115, 115, 0.4); } 70% { box-shadow: 0 0 0 10px rgba(249, 115, 115, 0); } 100% { box-shadow: 0 0 0 0 rgba(249, 115, 115, 0); } }
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

        <div class="card logs-section">
            <div class="card-header">Detection Events</div>
            <div class="table-container">
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

                        // features panel: render ordered table with formatted values and progress
                        const featuresTableBody = document.querySelector('#features-table tbody');
                        featuresTableBody.innerHTML = '';
                        const order = data.feature_order && data.feature_order.length ? data.feature_order : FEATURE_ORDER;
                        order.forEach(k=>{
                                const val = (data.last_features && data.last_features[k]) ? Number(data.last_features[k]) : 0;
                                const display = (Math.abs(val) >= 1000) ? Number(val).toFixed(0) : Number(val).toFixed(2);
                                const max = k.includes('count') ? 1000 : 1500;
                                const pct = Math.min(100, Math.round((val / max) * 100));
                                const row = `
                                        <tr>
                                            <td style="width:120px;padding:6px 8px;color:#cfe6ff;font-weight:600">${k}</td>
                                            <td style="width:80px;padding:6px 8px">${display}</td>
                                            <td style="padding:6px 8px;min-width:120px">
                                                <div class="progress-bg"><div class="progress-fill" style="width:${pct}%"></div></div>
                                            </td>
                                        </tr>`;
                                featuresTableBody.innerHTML += row;
                        });

            // logs (append into scrollable container without resizing page)
            const alertsContainer = document.getElementById('alerts-container');
            const logsBody = document.getElementById('logsBody');
            const wasAtBottom = (alertsContainer.scrollHeight - alertsContainer.clientHeight - alertsContainer.scrollTop) < 50;
            logsBody.innerHTML = '';
            globalAlerts = data.alerts || [];
            (data.alerts || []).slice().reverse().forEach(a=>{
                const ts = a.timestamp || new Date().toLocaleTimeString();
                const row = `<tr><td style="padding:6px 8px">${ts}</td><td class="log-alert" style="padding:6px 8px">${a.event_type || 'DDoS'}</td><td style="padding:6px 8px">${(a.score||0).toFixed(4)}</td></tr>`;
                logsBody.innerHTML += row;
            });
            if (wasAtBottom) alertsContainer.scrollTop = alertsContainer.scrollHeight;
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
    // Jump-to-latest button behavior
    const scrollBtn = document.getElementById('scrollBtn');
    if (scrollBtn) {
        scrollBtn.addEventListener('click', () => {
            const c = document.getElementById('alerts-container'); if (c) c.scrollTop = c.scrollHeight;
        });
    }

    // Clock sync: update header clock every second (uses client/browser time)
    function updateNowClock(){
        try{const el = document.getElementById('now-clock'); if(el) el.innerText = new Date().toLocaleTimeString();}catch(e){}
    }
    updateNowClock();
    setInterval(updateNowClock, 1000);

    window.addEventListener('resize', () => { if(window.trafficChart) window.trafficChart.resize(); });
    setInterval(updateDashboard, 1000);
    updateDashboard();
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
    payload = request.json or {}

    # Accept both legacy small payloads and the new full structured payload
    if 'last_score' in payload or 'last_features' in payload:
        # New structured payload from updated detector
        last_score = float(payload.get('last_score', payload.get('score', 0.0)))
        is_attack = bool(payload.get('is_attack', payload.get('attack', False)))
        last_features = payload.get('last_features', payload.get('features', {}) ) or {}
        traffic_history = payload.get('traffic_history', []) or []
        alerts = payload.get('alerts', []) or []

        STATE['last_score'] = last_score
        STATE['is_attack'] = is_attack
        STATE['last_update'] = time.time()
        if isinstance(last_features, dict):
            for k in STATE['feature_order']:
                STATE['last_features'][k] = float(last_features.get(k, 0))

        # merge/append traffic history entries
        try:
            for entry in traffic_history:
                if isinstance(entry, dict) and 'packets' in entry:
                    STATE['traffic_history'].append({'packets': float(entry.get('packets',0)), 'bytes': float(entry.get('bytes',0)), 'timestamp': float(entry.get('timestamp', time.time()))})
        except Exception:
            pass

        # append alerts (keep most recent 1000)
        try:
            for a in alerts:
                if isinstance(a, dict) and 'timestamp' in a:
                    STATE['alerts'].append(a)
            STATE['alerts'] = STATE['alerts'][-1000:]
        except Exception:
            pass

    else:
        # Backward-compatible handling for small payloads: {score, attack, features}
        score = float(payload.get('score', 0))
        attack = bool(payload.get('attack', False))
        features = payload.get('features', {}) or {}

        STATE['last_score'] = score
        STATE['is_attack'] = attack
        STATE['last_update'] = time.time()
        if isinstance(features, dict):
            for k in STATE['feature_order']:
                STATE['last_features'][k] = float(features.get(k, 0))
            STATE['traffic_history'].append({'packets': float(features.get('packet_count',0)), 'bytes': float(features.get('byte_count',0)), 'timestamp': time.time()})
        if attack:
            STATE['alerts'].append({'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'), 'event_type': 'DDoS', 'score': score, 'metadata': features})
            STATE['alerts'] = STATE['alerts'][-1000:]

    return jsonify(success=True)


@app.route('/api/state')
def api_state():
    return jsonify({'last_score':STATE['last_score'],'is_attack':STATE['is_attack'],'last_update':STATE['last_update'],'last_features':STATE['last_features'],'feature_order':STATE['feature_order'],'traffic_history':list(STATE['traffic_history']),'alerts':STATE['alerts']})


if __name__=='__main__':
    app.run(host='0.0.0.0',port=5000,debug=False)

*** End Patchfrom flask import Flask, jsonify, render_template_string, request
import time
from collections import deque
from pathlib import Path
import json

app = Flask(__name__)

if __name__=='__main__':
    app.run(host='0.0.0.0',port=5000,debug=False)
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

        <div class="card logs-section">
            <div class="card-header">Detection Events</div>
            <div class="table-container">
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
            document.getElementById('scoreVal').style.color = data.last_score > 0.5 ? '#ef4444' : '#f1f5f9';

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
    setInterval(updateDashboard, 1000);
    updateDashboard();
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
    payload = request.json or {}

    # Accept both legacy small payloads and the new full structured payload
    if 'last_score' in payload or 'last_features' in payload:
        # New structured payload from updated detector
        last_score = float(payload.get('last_score', payload.get('score', 0.0)))
        is_attack = bool(payload.get('is_attack', payload.get('attack', False)))
        last_features = payload.get('last_features', payload.get('features', {}) ) or {}
        traffic_history = payload.get('traffic_history', []) or []
        alerts = payload.get('alerts', []) or []

        STATE['last_score'] = last_score
        STATE['is_attack'] = is_attack
        STATE['last_update'] = time.time()
        if isinstance(last_features, dict):
            for k in STATE['feature_order']:
                STATE['last_features'][k] = float(last_features.get(k, 0))

        # merge/append traffic history entries
        try:
            for entry in traffic_history:
                if isinstance(entry, dict) and 'packets' in entry:
                    STATE['traffic_history'].append({'packets': float(entry.get('packets',0)), 'bytes': float(entry.get('bytes',0)), 'timestamp': float(entry.get('timestamp', time.time()))})
        except Exception:
            pass

        # append alerts (keep most recent 1000)
        try:
            for a in alerts:
                if isinstance(a, dict) and 'timestamp' in a:
                    STATE['alerts'].append(a)
            STATE['alerts'] = STATE['alerts'][-1000:]
        except Exception:
            pass

    else:
        # Backward-compatible handling for small payloads: {score, attack, features}
        score = float(payload.get('score', 0))
        attack = bool(payload.get('attack', False))
        features = payload.get('features', {}) or {}

        STATE['last_score'] = score
        STATE['is_attack'] = attack
        STATE['last_update'] = time.time()
        if isinstance(features, dict):
            for k in STATE['feature_order']:
                STATE['last_features'][k] = float(features.get(k, 0))
            STATE['traffic_history'].append({'packets': float(features.get('packet_count',0)), 'bytes': float(features.get('byte_count',0)), 'timestamp': time.time()})
        if attack:
            STATE['alerts'].append({'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'), 'event_type': 'DDoS', 'score': score, 'metadata': features})
            STATE['alerts'] = STATE['alerts'][-1000:]

    return jsonify(success=True)


@app.route('/api/state')
def api_state():
    return jsonify({'last_score':STATE['last_score'],'is_attack':STATE['is_attack'],'last_update':STATE['last_update'],'last_features':STATE['last_features'],'feature_order':STATE['feature_order'],'traffic_history':list(STATE['traffic_history']),'alerts':STATE['alerts']})


if __name__=='__main__':
    app.run(host='0.0.0.0',port=5000,debug=False)
"""
Clean SIEM dashboard application.

This file provides a Flask app with:
- A dark SIEM-like UI (Chart.js-based)
- API endpoints `/api/update` for detector POSTs and `/api/state` for UI polling

The HTML is embedded as a triple-quoted string and a placeholder is replaced
with the JSON-serialized `FEATURE_ORDER` to avoid accidental `%` formatting.
"""

from flask import Flask, jsonify, render_template_string, request
import time
from collections import deque
from pathlib import Path
import json

app = Flask(__name__)

# Load feature order from file if present
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
    "last_score": 0.0,
    "is_attack": False,
    "last_update": 0,
    "last_features": {k: 0 for k in FEATURE_ORDER},
    "feature_order": FEATURE_ORDER,
    "traffic_history": deque(maxlen=60),
    "alerts": [],
}


HTML_PAGE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>SIEM - DDoS Detection</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
  <style>
    :root{ --bg:#0b0f14; --panel:#0f1720; --muted:#9aa4b2; --red:#f85149; --blue:#58a6ff; }
    html,body{height:100%;margin:0;background:var(--bg);color:#e6eef6;font-family:Inter,Segoe UI,Arial}
    .container{display:grid;grid-template-columns:320px 1fr;grid-template-rows:72px 1fr;gap:14px;height:100vh;padding:12px;box-sizing:border-box}
    .header{grid-column:1/3;border-radius:8px;display:flex;align-items:center;justify-content:space-between;padding:14px 22px}
    .brand{display:flex;align-items:center;gap:14px}
    .title{font-size:20px;font-weight:700}
    .pulse{animation: pulse 1s infinite;}
    @keyframes pulse{0%{box-shadow:0 0 0 0 rgba(248,81,73,0.4)}50%{box-shadow:0 0 0 8px rgba(248,81,73,0)}100%{box-shadow:0 0 0 0 rgba(248,81,73,0)}}
    .sidebar{background:var(--panel);border-radius:8px;padding:18px;overflow:auto;min-width:260px}
    .main{background:transparent;display:grid;grid-template-rows:280px 1fr;gap:14px}
    .card{background:var(--panel);border-radius:8px;padding:18px;box-shadow:0 1px 0 rgba(255,255,255,0.02)}
    h2{margin:0;color:var(--muted);font-weight:600;font-size:14px}
    .feature{display:flex;align-items:center;justify-content:space-between;margin:10px 0}
    .feature > div:first-child{min-width:140px;font-size:13px}
    .bar{height:12px;background:#0b1014;border-radius:8px;flex:1;margin-left:12px;overflow:hidden}
    .bar > i{display:block;height:100%;background:var(--blue);width:0;transition:width .35s ease}
    .bar.attack > i{background:var(--red)}
    .table{width:100%;border-collapse:collapse;color:#cfe6ff;font-size:13px}
    .table th{color:var(--muted);text-align:left;padding:10px}
    .table td{padding:10px;border-top:1px solid rgba(255,255,255,0.03)}
    .metric {display:flex;gap:12px;align-items:center}
    .metric .value{font-size:22px;font-weight:800}
    #trafficChart{width:100% !important;height:260px !important;display:block}
    @media (max-width: 900px){.container{grid-template-columns:1fr;grid-template-rows:96px 1fr;gap:10px;padding:10px}.header{grid-column:1/2}.sidebar{order:2;min-width:0}.main{order:1}.feature > div:first-child{min-width:100px}#trafficChart{height:220px !important}}
  </style>
</head>
<body>
  <div class="container">
    <div class="header card" id="header">
      <div class="brand">
        <div class="logo" style="width:40px;height:40px;border-radius:6px;background:linear-gradient(135deg,var(--blue),var(--red))"></div>
        <div>
          <div class="title">SIEM — AI DDoS Detection</div>
          <div style="font-size:12px;color:var(--muted)">Real-time network security insights</div>
        </div>
      </div>
      <div style="display:flex;gap:18px;align-items:center">
        <div id="status-pill" style="padding:8px 12px;border-radius:999px;background:rgba(88,166,255,0.08);color:var(--blue);font-weight:700">Normal</div>
        <div style="font-size:12px;color:var(--muted)">Last update: <span id="last-update">-</span></div>
      </div>
    </div>
    <aside class="sidebar card">
      <h2>AI Insights</h2>
      <div id="feature-list"></div>
    </aside>
    <main class="main">
      <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
          <h2>Live Traffic</h2>
          <div class="metric"><div style="color:var(--muted);font-size:12px">Packets/s</div><div class="value" id="packets-val">0</div></div>
        </div>
        <canvas id="trafficChart"></canvas>
      </div>
      <div style="display:grid;grid-template-columns:1fr 420px;gap:16px">
        <div class="card">
          <h2>SIEM Log</h2>
          <table class="table" id="alerts-table"><thead><tr><th>Timestamp</th><th>Event Type</th><th>Confidence</th><th>Metadata</th></tr></thead><tbody></tbody></table>
        </div>
        <div class="card">
          <h2>Last Features</h2>
          <pre id="features" style="white-space:pre-wrap;font-size:13px"></pre>
        </div>
      </div>
    </main>
  </div>
<script>
const FEATURE_ORDER = __FEATURE_ORDER__;
const RED = '#f85149', BLUE = '#58a6ff';
const featureList = document.getElementById('feature-list');
FEATURE_ORDER.forEach(k => { const el = document.createElement('div'); el.className='feature'; el.innerHTML = `<div style="min-width:120px">${k}</div><div class="bar" id="bar-${k}"><i style="width:0%"></i></div><div style="width:50px;text-align:right" id="val-${k}">0</div>`; featureList.appendChild(el); });
const ctx = document.getElementById('trafficChart').getContext('2d');
const trafficChart = new Chart(ctx, { type: 'line', data: {labels: [], datasets:[{label:'Packets/sec',data:[],borderColor:BLUE,backgroundColor:'rgba(88,166,255,0.08)',yAxisID:'y'},{label:'Bytes/sec',data:[],borderColor:RED,backgroundColor:'rgba(248,81,73,0.06)',yAxisID:'y1'}]}, options: {responsive:true,maintainAspectRatio:false,scales:{y:{position:'left',beginAtZero:true},y1:{position:'right',beginAtZero:true,grid:{drawOnChartArea:false}}}} });
function setBar(name, value, attack){ const pct = Math.min(100, Math.round(value)); const bar = document.getElementById('bar-'+name); if(!bar) return; const i = bar.querySelector('i'); i.style.width = pct + '%'; i.style.background = attack ? RED : BLUE; const v = document.getElementById('val-'+name); if(v) v.innerText = Number(value).toFixed(2); }
function addAlertRow(a){ const tbody = document.querySelector('#alerts-table tbody'); const tr = document.createElement('tr'); tr.innerHTML = `<td>${a.timestamp}</td><td>${a.event_type}</td><td>${(a.score||0).toFixed(4)}</td><td><pre style="white-space:pre-wrap">${JSON.stringify(a.metadata||{},null,0)}</pre></td>`; tbody.prepend(tr); while(tbody.children.length>200) tbody.removeChild(tbody.lastChild); }
function refresh(){ fetch('/api/state').then(r=>r.json()).then(data=>{ document.getElementById('last-update').innerText = new Date((data.last_update||0)*1000).toLocaleTimeString(); const isAttack = !!data.is_attack; const status = document.getElementById('status-pill'); status.innerText = isAttack ? 'DDoS Alert' : 'Normal'; status.style.background = isAttack ? 'rgba(248,81,73,0.12)' : 'rgba(88,166,255,0.08)'; status.style.color = isAttack ? RED : BLUE; const header = document.getElementById('header'); if(isAttack) header.classList.add('pulse'); else header.classList.remove('pulse'); const features = data.last_features || {}; FEATURE_ORDER.forEach(k => { setBar(k, features[k] || 0, isAttack); }); document.getElementById('features').innerText = JSON.stringify(features, null, 2); const history = data.traffic_history || []; const labels = history.map(h=>new Date((h.timestamp||0)*1000).toLocaleTimeString()); trafficChart.data.labels = labels; trafficChart.data.datasets[0].data = history.map(h=>h.packets||0); trafficChart.data.datasets[1].data = history.map(h=>h.bytes||0); trafficChart.update('none'); const last = history[history.length-1]||{}; document.getElementById('packets-val').innerText = (last.packets||0).toFixed(0); const alerts = data.alerts || []; const existing = document.querySelectorAll('#alerts-table tbody tr'); if(alerts.length>0){ const top = alerts[alerts.length-1]; if(!existing.length || existing[0].cells[0].innerText !== top.timestamp){ document.querySelector('#alerts-table tbody').innerHTML = ''; alerts.slice(-200).reverse().forEach(a=>addAlertRow(a)); } } }).catch(()=>{}); }
setInterval(refresh, 1000); refresh();
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
    score = float(data.get('score', 0))
    attack = bool(data.get('attack', False))
    features = data.get('features', {}) or {}

    STATE['last_score'] = score
    STATE['is_attack'] = attack
    STATE['last_update'] = time.time()
    if isinstance(features, dict):
        STATE['last_features'].update({k: float(features.get(k, 0)) for k in STATE['feature_order']})
        packets = float(features.get('packet_count', 0))
        bytes_count = float(features.get('byte_count', 0))
        STATE['traffic_history'].append({ 'packets': packets, 'bytes': bytes_count, 'timestamp': time.time() })

    if attack:
        alert = { 'timestamp': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()), 'event_type': 'DDoS', 'score': score, 'metadata': features }
        STATE['alerts'].append(alert)
        STATE['alerts'] = STATE['alerts'][-1000:]

    return jsonify(success=True)


@app.route('/api/state')
def api_state():
    copy = { 'last_score': STATE['last_score'], 'is_attack': STATE['is_attack'], 'last_update': STATE['last_update'], 'last_features': STATE['last_features'], 'feature_order': STATE['feature_order'], 'traffic_history': list(STATE['traffic_history']), 'alerts': STATE['alerts'] }
    return jsonify(copy)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
from flask import Flask, jsonify, render_template_string, request
import time
from collections import deque
from pathlib import Path
import json

app = Flask(__name__)

# Load feature order from file if present
FEATURE_FILE = Path(__file__).parent / 'feature_columns.json'
try:
    FEATURE_ORDER = json.loads(FEATURE_FILE.read_text())
except Exception:
    FEATURE_ORDER = [
        "packet_count","byte_count","avg_pkt_size","std_pkt_size","duration_sec",
        "unique_src_ips","unique_dst_ips","tcp_count","udp_count","icmp_count"
    ]

# Shared state
  <style>
    :root{
      --bg:#0b0f14; --panel:#0f1720; --muted:#9aa4b2; --red:#f85149; --blue:#58a6ff; --accent:#22313a;
    }
    html,body{height:100%;margin:0;background:var(--bg);color:#e6eef6;font-family:Inter,Segoe UI,Arial}
    /* Layout grid: slightly wider sidebar and slightly taller header */
    .container{display:grid;grid-template-columns:320px 1fr;grid-template-rows:72px 1fr;gap:14px;height:100vh;padding:12px;box-sizing:border-box}
    .header{grid-column:1/3;background:linear-gradient(90deg,rgba(255,255,255,0.02),rgba(0,0,0,0.05));border-radius:8px;display:flex;align-items:center;justify-content:space-between;padding:14px 22px}
    .brand{display:flex;align-items:center;gap:14px}
    .title{font-size:20px;font-weight:700}
    .pulse{animation: pulse 1s infinite;}
    @keyframes pulse{0%{box-shadow:0 0 0 0 rgba(248,81,73,0.4)}50%{box-shadow:0 0 0 8px rgba(248,81,73,0)}100%{box-shadow:0 0 0 0 rgba(248,81,73,0)}}

    .sidebar{background:var(--panel);border-radius:8px;padding:18px;overflow:auto;min-width:260px}
    .main{background:transparent;display:grid;grid-template-rows:280px 1fr;gap:14px}
    .card{background:var(--panel);border-radius:8px;padding:18px;box-shadow:0 1px 0 rgba(255,255,255,0.02)}
    h2{margin:0;color:var(--muted);font-weight:600;font-size:14px}

    .feature{display:flex;align-items:center;justify-content:space-between;margin:10px 0}
    .feature > div:first-child{min-width:140px;font-size:13px}
    .bar{height:12px;background:#0b1014;border-radius:8px;flex:1;margin-left:12px;overflow:hidden}
    .bar > i{display:block;height:100%;background:var(--blue);width:0;transition:width .35s ease}
    .bar.attack > i{background:var(--red)}

    .table{width:100%;border-collapse:collapse;color:#cfe6ff;font-size:13px}
    .table th{color:var(--muted);text-align:left;padding:10px}
    .table td{padding:10px;border-top:1px solid rgba(255,255,255,0.03)}

    .metric {display:flex;gap:12px;align-items:center}
    .metric .value{font-size:22px;font-weight:800}

    /* Chart canvas sizing */
    #trafficChart{width:100% !important;height:260px !important;display:block}

    /* Responsive: collapse to single column on small screens */
    @media (max-width: 900px){
      .container{grid-template-columns:1fr;grid-template-rows:96px 1fr;gap:10px;padding:10px}
      .header{grid-column:1/2}
      .sidebar{order:2;min-width:0}
      .main{order:1}
      .feature > div:first-child{min-width:100px}
      #trafficChart{height:220px !important}
    }
  </style>
    .header{grid-column:1/3;background:linear-gradient(90deg,rgba(255,255,255,0.02),rgba(0,0,0,0.05));border-radius:8px;display:flex;align-items:center;justify-content:space-between;padding:12px 20px}
    .brand{display:flex;align-items:center;gap:12px}
    .title{font-size:18px;font-weight:700}
    .pulse{animation: pulse 1s infinite;}
    @keyframes pulse{0%{box-shadow:0 0 0 0 rgba(248,81,73,0.4)}50%{box-shadow:0 0 0 8px rgba(248,81,73,0)}100%{box-shadow:0 0 0 0 rgba(248,81,73,0)}}

    .sidebar{background:var(--panel);border-radius:8px;padding:16px;overflow:auto}
    .main{background:transparent;display:grid;grid-template-rows:260px 1fr;gap:16px}
    .card{background:var(--panel);border-radius:8px;padding:14px;box-shadow:0 1px 0 rgba(255,255,255,0.02)}
    h2{margin:0;color:var(--muted);font-weight:600}

    .feature{display:flex;align-items:center;justify-content:space-between;margin:10px 0}
    .bar{height:10px;background:#0b1014;border-radius:8px;flex:1;margin-left:12px;overflow:hidden}
    .bar > i{display:block;height:100%;background:var(--blue);width:0}
    .bar.attack > i{background:var(--red)}

    .table{width:100%;border-collapse:collapse;color:#cfe6ff;font-size:13px}
    .table th{color:var(--muted);text-align:left;padding:8px}
    .table td{padding:8px;border-top:1px solid rgba(255,255,255,0.03)}

    .metric {display:flex;gap:12px;align-items:center}
    .metric .value{font-size:20px;font-weight:700}
  </style>
</head>
<body>
  <div class="container">
    <div class="header card" id="header">
      <div class="brand">
        <div class="logo" style="width:40px;height:40px;border-radius:6px;background:linear-gradient(135deg,var(--blue),var(--red))"></div>
        <div>
          <div class="title">SIEM — AI DDoS Detection</div>
          <div style="font-size:12px;color:var(--muted)">Real-time network security insights</div>
        </div>
      </div>
      <div style="display:flex;gap:18px;align-items:center">
        <div id="status-pill" style="padding:8px 12px;border-radius:999px;background:rgba(88,166,255,0.08);color:var(--blue);font-weight:700">Normal</div>
        <div style="font-size:12px;color:var(--muted)">Last update: <span id="last-update">-</span></div>
      </div>
    </div>

    <aside class="sidebar card">
      <h2>AI Insights</h2>
      <div id="feature-list">
        <!-- Dynamically populated -->
      </div>
    </aside>

    <main class="main">
      <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
          <h2>Live Traffic</h2>
          <div class="metric"><div style="color:var(--muted);font-size:12px">Packets/s</div><div class="value" id="packets-val">0</div></div>
        </div>
        <canvas id="trafficChart" style="height:220px;width:100%"></canvas>
      </div>

      <div style="display:grid;grid-template-columns:1fr 420px;gap:16px">
        <div class="card">
          <h2>SIEM Log</h2>
          <table class="table" id="alerts-table">
            <thead><tr><th>Timestamp</th><th>Event Type</th><th>Confidence</th><th>Metadata</th></tr></thead>
            <tbody></tbody>
          </table>
        </div>

        <div class="card">
          <h2>Last Features</h2>
          <pre id="features" style="white-space:pre-wrap;font-size:13px"></pre>
        </div>
      </div>
    </main>
  </div>

<script>
const FEATURE_ORDER = __FEATURE_ORDER__;
const RED = '#f85149', BLUE = '#58a6ff';

// Build feature list UI
const featureList = document.getElementById('feature-list');
FEATURE_ORDER.forEach(k => {
  const el = document.createElement('div'); el.className='feature';
  el.innerHTML = `<div style="min-width:120px">${k}</div><div class="bar" id="bar-${k}"><i style="width:0%"></i></div><div style="width:50px;text-align:right" id="val-${k}">0</div>`;
  featureList.appendChild(el);
});

// Chart.js dual-axis
const ctx = document.getElementById('trafficChart').getContext('2d');
const trafficChart = new Chart(ctx, {
  type: 'line',
  data: {labels: [], datasets:[{label:'Packets/sec',data:[],borderColor:BLUE,backgroundColor:'rgba(88,166,255,0.08)',yAxisID:'y'},{label:'Bytes/sec',data:[],borderColor:RED,backgroundColor:'rgba(248,81,73,0.06)',yAxisID:'y1'}]},
  options: {responsive:true,maintainAspectRatio:false,scales:{y:{position:'left',beginAtZero:true},y1:{position:'right',beginAtZero:true,grid:{drawOnChartArea:false}}}}
});

function setBar(name, value, attack){
  const pct = Math.min(100, Math.round(value));
  const bar = document.getElementById('bar-'+name);
  if(!bar) return;
  const i = bar.querySelector('i');
  i.style.width = pct + '%';
  i.style.background = attack ? RED : BLUE;
  const v = document.getElementById('val-'+name);
  if(v) v.innerText = Number(value).toFixed(2);
}

function addAlertRow(a){
  const tbody = document.querySelector('#alerts-table tbody');
  const tr = document.createElement('tr');
  tr.innerHTML = `<td>${a.timestamp}</td><td>${a.event_type}</td><td>${(a.score||0).toFixed(4)}</td><td><pre style="white-space:pre-wrap">${JSON.stringify(a.metadata||{},null,0)}</pre></td>`;
  tbody.prepend(tr);
  // keep 200 rows
  while(tbody.children.length>200) tbody.removeChild(tbody.lastChild);
}

function refresh(){
  fetch('/api/state').then(r=>r.json()).then(data=>{
    document.getElementById('last-update').innerText = new Date((data.last_update||0)*1000).toLocaleTimeString();
    const isAttack = !!data.is_attack;
    const status = document.getElementById('status-pill');
    status.innerText = isAttack ? 'DDoS Alert' : 'Normal';
    status.style.background = isAttack ? 'rgba(248,81,73,0.12)' : 'rgba(88,166,255,0.08)';
    status.style.color = isAttack ? RED : BLUE;
    const header = document.getElementById('header');
    if(isAttack) header.classList.add('pulse'); else header.classList.remove('pulse');

    // Update features
    const features = data.last_features || {};
    FEATURE_ORDER.forEach(k => {
      setBar(k, features[k] || 0, isAttack);
    });

    // Update features text
    document.getElementById('features').innerText = JSON.stringify(features, null, 2);

    // Update traffic chart
    const history = data.traffic_history || [];
    const labels = history.map(h=>new Date((h.timestamp||0)*1000).toLocaleTimeString());
    trafficChart.data.labels = labels;
    trafficChart.data.datasets[0].data = history.map(h=>h.packets||0);
    trafficChart.data.datasets[1].data = history.map(h=>h.bytes||0);
    trafficChart.update('none');

    // packets meta
    const last = history[history.length-1]||{};
    document.getElementById('packets-val').innerText = (last.packets||0).toFixed(0);

    // Alerts
    const alerts = data.alerts || [];
    // Display newest first
    const existing = document.querySelectorAll('#alerts-table tbody tr');
    if(alerts.length>0){
      // if top alert is different from table top, update table
      const top = alerts[alerts.length-1];
      if(!existing.length || existing[0].cells[0].innerText !== top.timestamp){
        // rebuild a few latest rows
        document.querySelector('#alerts-table tbody').innerHTML = '';
        alerts.slice(-200).reverse().forEach(a=>addAlertRow(a));
      }
    }
  }).catch(()=>{});
}

setInterval(refresh, 1000);
refresh();
</script>
</body>
</html>
"""

# Safely inject JSON without using old-style % formatting (avoids '%' collisions)
HTML_PAGE = HTML_PAGE.replace('__FEATURE_ORDER__', json.dumps(FEATURE_ORDER))


@app.route('/')
def index():
    return render_template_string(HTML_PAGE)


@app.route('/api/update', methods=['POST'])
def api_update():
    data = request.json or {}
    score = float(data.get('score', 0))
    attack = bool(data.get('attack', False))
    features = data.get('features', {}) or {}

    STATE['last_score'] = score
    STATE['is_attack'] = attack
    STATE['last_update'] = time.time()
    # Ensure feature keys exist
    if isinstance(features, dict):
        STATE['last_features'].update({k: float(features.get(k, 0)) for k in STATE['feature_order']})
        # update traffic history using packet_count/byte_count if present
        packets = float(features.get('packet_count', 0))
        bytes_count = float(features.get('byte_count', 0))
        STATE['traffic_history'].append({
            'packets': packets,
            'bytes': bytes_count,
            'timestamp': time.time()
        })

    if attack:
        alert = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()),
            'event_type': 'DDoS',
            'score': score,
            'metadata': features
        }
        STATE['alerts'].append(alert)
        STATE['alerts'] = STATE['alerts'][-1000:]

    return jsonify(success=True)


@app.route('/api/state')
def api_state():
    copy = {
        'last_score': STATE['last_score'],
        'is_attack': STATE['is_attack'],
        'last_update': STATE['last_update'],
        'last_features': STATE['last_features'],
        'feature_order': STATE['feature_order'],
        'traffic_history': list(STATE['traffic_history']),
        'alerts': STATE['alerts']
    }
    return jsonify(copy)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
