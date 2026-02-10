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
        from dashboard_app import app

        if __name__ == "__main__":
            # Run the new SIEM-style dashboard (dashboard_app.py)
            app.run(host="0.0.0.0", port=5000, debug=False)
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
