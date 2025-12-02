from flask import Flask, jsonify, render_template_string, request
import time
import threading
from collections import deque

app = Flask(__name__)

# ------------------------------------------------------
# Shared state (updated by detector in real-time)
# ------------------------------------------------------
STATE = {
    "last_score": 0.0,
    "is_attack": False,
    "last_update": 0,
    "alerts": [],
    "last_features": {},
    "feature_order": [],
    # Keep last 60 data points (1 minute at 1 sec intervals)
    "traffic_history": deque(maxlen=60),
}

# ------------------------------------------------------
# HTML Dashboard Page
# ------------------------------------------------------
HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>DDoS Detection Dashboard</title>
    <style>
        body { font-family: Arial; margin: 40px; }
        .card { padding: 20px; margin-bottom: 20px; border: 1px solid #ccc; border-radius: 8px; }
        .good { color: green; }
        .bad { color: red; font-weight: bold; }
        .section-title { font-size: 22px; margin-bottom: 10px; }
        #trafficChartContainer { width: 100%; height: 300px; position: relative; }
        #trafficChart { width: 100% !important; height: 300px !important; }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
</head>
<body>
    <h1>DDoS Detection Dashboard</h1>

    <div class="card">
        <div class="section-title">Real-Time Prediction</div>
        <div id="score">Loading...</div>
        <div id="status"></div>
    </div>

    <div class="card">
        <div class="section-title">Network Traffic</div>
        <div id="trafficChartContainer">
            <canvas id="trafficChart"></canvas>
        </div>
    </div>

    <div class="card">
        <div class="section-title">Latest Extracted Features</div>
        <pre id="features"></pre>
    </div>

    <div class="card">
        <div class="section-title">Alerts</div>
        <ul id="alerts"></ul>
    </div>

<script>
// Initialize traffic chart with FIXED scaling
const FIXED_MAX_PACKETS = 10000;  // Fixed max for packets/sec
const FIXED_MAX_BYTES = 10000000;  // Fixed max for bytes/sec (10 MB)

const ctx = document.getElementById('trafficChart').getContext('2d');
const trafficChart = new Chart(ctx, {
    type: 'line',
    data: {
        labels: [],
        datasets: [
            {
                label: 'Packets/sec',
                data: [],
                borderColor: 'rgb(75, 192, 192)',
                backgroundColor: 'rgba(75, 192, 192, 0.2)',
                tension: 0.1,
                yAxisID: 'y'
            },
            {
                label: 'Bytes/sec',
                data: [],
                borderColor: 'rgb(255, 99, 132)',
                backgroundColor: 'rgba(255, 99, 132, 0.2)',
                tension: 0.1,
                yAxisID: 'y1'
            }
        ]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: {
            mode: 'index',
            intersect: false,
        },
        scales: {
            y: {
                type: 'linear',
                display: true,
                position: 'left',
                beginAtZero: true,
                min: 0,
                max: FIXED_MAX_PACKETS,
                title: {
                    display: true,
                    text: 'Packets/sec'
                },
                ticks: {
                    stepSize: FIXED_MAX_PACKETS / 10
                }
            },
            y1: {
                type: 'linear',
                display: true,
                position: 'right',
                beginAtZero: true,
                min: 0,
                max: FIXED_MAX_BYTES,
                title: {
                    display: true,
                    text: 'Bytes/sec'
                },
                ticks: {
                    stepSize: FIXED_MAX_BYTES / 10,
                    callback: function(value) {
                        if (value >= 1000000) return (value / 1000000).toFixed(1) + 'M';
                        if (value >= 1000) return (value / 1000).toFixed(1) + 'K';
                        return value;
                    }
                },
                grid: {
                    drawOnChartArea: false,
                },
            },
            x: {
                title: {
                    display: true,
                    text: 'Time'
                }
            }
        },
        plugins: {
            legend: {
                display: true,
                position: 'top'
            },
            tooltip: {
                mode: 'index',
                intersect: false
            }
        }
    }
});

function refresh() {
    fetch("/api/state")
      .then(r => r.json())
      .then(data => {
          document.getElementById("score").innerHTML =
              "Score: " + data.last_score.toFixed(4);

          if (data.is_attack)
              document.getElementById("status").innerHTML =
                  "<span class='bad'>DDoS Detected</span>";
          else
              document.getElementById("status").innerHTML =
                  "<span class='good'>Normal Traffic</span>";

          // Update traffic chart (with fixed Y-axis ranges)
          if (data.traffic_history && data.traffic_history.length > 0) {
              const history = data.traffic_history;
              const labels = history.map((_, i) => {
                  const now = new Date();
                  const secondsAgo = history.length - i - 1;
                  const time = new Date(now.getTime() - secondsAgo * 1000);
                  return time.toLocaleTimeString();
              });
              
              trafficChart.data.labels = labels;
              trafficChart.data.datasets[0].data = history.map(d => d.packets || 0);
              trafficChart.data.datasets[1].data = history.map(d => d.bytes || 0);
              trafficChart.update('none'); // 'none' mode for smooth updates
          }

          // Features
          if (Array.isArray(data.last_features)) {
              document.getElementById("features").innerText =
                  JSON.stringify(data.last_features, null, 2);
          } else {
              const entries = data.feature_order.length
                ? data.feature_order.map(k => `${k}: ${data.last_features[k] ?? 0}`)
                : Object.entries(data.last_features).map(([k, v]) => `${k}: ${v}`);
              document.getElementById("features").innerText = entries.join("\\n");
          }

          // Alerts
          let alertBox = document.getElementById("alerts");
          alertBox.innerHTML = "";
          data.alerts.slice().reverse().forEach(a => {
              let li = document.createElement("li");
              li.innerText = a;
              alertBox.appendChild(li);
          });
      });
}

setInterval(refresh, 1000);
refresh();
</script>

</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(HTML_PAGE)

# ------------------------------------------------------
# API endpoint: detector pushes updated prediction
# ------------------------------------------------------


@app.route("/api/update", methods=["POST"])
def update_state():
    data = request.json
    STATE["last_score"] = data.get("score", 0)
    STATE["is_attack"] = data.get("attack", False)
    STATE["last_features"] = data.get("features", [])
    STATE["last_update"] = time.time()
    STATE["feature_order"] = data.get("feature_order", STATE["feature_order"])

    # Update traffic history
    features = data.get("features", {})
    if isinstance(features, dict):
        packets = features.get("packet_count", 0)
        bytes_count = features.get("byte_count", 0)
        STATE["traffic_history"].append({
            "packets": packets,
            "bytes": bytes_count,
            "timestamp": time.time()
        })

    if data.get("attack", False):
        alert = f"{time.strftime('%Y-%m-%d %H:%M:%S')} — DDoS detected (score={data['score']:.4f})"
        STATE["alerts"].append(alert)
        STATE["alerts"] = STATE["alerts"][-100:]  # keep last 100

    return jsonify(success=True)

# ------------------------------------------------------
# API endpoint: dashboard retrieves current state
# ------------------------------------------------------


@app.route("/api/state")
def get_state():
    # Convert deque to list for JSON serialization
    state_copy = STATE.copy()
    state_copy["traffic_history"] = list(STATE["traffic_history"])
    return jsonify(state_copy)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
