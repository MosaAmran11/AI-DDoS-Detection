# Required Libraries for DDoS Detector Project

This document lists all required and optional libraries for the three main components of the DDoS detection system.

## 📦 Core Requirements (All Files)

### Standard Library (Built-in - No Installation Needed)
- `time`
- `threading`
- `subprocess`
- `collections` (deque, Counter)
- `queue`
- `os`
- `sys`
- `json`
- `pathlib`
- `typing`

---

## 🎓 train.py - Training Script

### Required Third-Party Libraries

```bash
pip install numpy pandas scikit-learn tensorflow joblib
```

**Detailed list:**
- **numpy** - Numerical operations and arrays
- **pandas** - Data manipulation and CSV reading
- **scikit-learn** - Machine learning utilities
  - `sklearn.model_selection.train_test_split`
  - `sklearn.preprocessing.StandardScaler`
- **tensorflow** (or **tensorflow-cpu**) - Deep learning framework
  - `tensorflow.keras.layers` - Neural network layers
- **joblib** - Model serialization (saving/loading scaler)

### Optional
- **google.colab** - Only needed if running on Google Colab

---

## 🔍 realtime_transformer_detector.py - Real-Time Detector

### Required Third-Party Libraries

```bash
pip install numpy tensorflow joblib requests
```

**Detailed list:**
- **numpy** - Numerical operations and arrays
- **tensorflow** (or **tensorflow-cpu**) - Model loading and inference
  - `tensorflow.keras.models` - Model loading
- **joblib** - Loading the saved scaler
- **requests** - HTTP requests to dashboard API

### Optional (for Packet Capture - Choose One)

#### Option 1: pypcap (Windows - Recommended for High Performance)
```bash
# 1. Install Npcap: https://nmap.org/npcap/
# 2. Install Python packages:
pip install pypcap dpkt
```
- **pypcap** - High-speed packet capture (Windows with Npcap)
- **dpkt** - Fast packet parsing

#### Option 2: tcpdump (Linux - Recommended for High Performance)
```bash
# Usually pre-installed, but if not:
sudo apt-get install tcpdump
```
- **tcpdump** - System command (not a Python package)

#### Option 3: scapy (Fallback - Works on All Platforms)
```bash
pip install scapy
```
- **scapy** - Packet manipulation library (slower but universal)

**Note:** The script automatically detects your OS and uses the best available method:
- Windows → tries pypcap first, falls back to scapy
- Linux → tries tcpdump first, falls back to scapy
- Other → uses scapy

---

## 📊 dashboard.py - Web Dashboard

### Required Third-Party Libraries

```bash
pip install flask
```

**Detailed list:**
- **flask** - Web framework for the dashboard
  - `Flask` - Main application class
  - `jsonify` - JSON response helper
  - `render_template_string` - HTML rendering
  - `request` - HTTP request handling

---

## 📋 feature_config.py - Feature Configuration

### Required Third-Party Libraries

```bash
pip install numpy pandas
```

**Detailed list:**
- **numpy** - Numerical operations
- **pandas** - Data manipulation and JSON handling

---

## 🚀 Complete Installation Command

### For Training (train.py)
```bash
pip install numpy pandas scikit-learn tensorflow joblib
```

### For Real-Time Detection (realtime_transformer_detector.py)
```bash
# Minimum required
pip install numpy tensorflow joblib requests

# For high-speed packet capture on Windows
pip install pypcap dpkt
# Also install Npcap from: https://nmap.org/npcap/

# OR for high-speed packet capture on Linux
sudo apt-get install tcpdump

# OR fallback (works everywhere but slower)
pip install scapy
```

### For Dashboard (dashboard.py)
```bash
pip install flask
```

---

## 📦 All-in-One Installation

### Complete Setup (All Features)
```bash
# Core ML libraries
pip install numpy pandas scikit-learn tensorflow joblib

# Dashboard
pip install flask

# Real-time detector
pip install requests

# Packet capture (choose based on OS):
# Windows (recommended):
pip install pypcap dpkt
# Download Npcap from: https://nmap.org/npcap/

# OR Linux (recommended):
# tcpdump usually pre-installed

# OR Fallback (universal but slower):
pip install scapy
```

---

## 🔧 Version Recommendations

For best compatibility (especially with Python 3.11):

```bash
pip install numpy==1.26.4 pandas==2.2.0 scikit-learn==1.5.2 tensorflow-cpu==2.17.0 joblib==1.4.2 flask==3.0.0 requests==2.32.0

# Optional packet capture:
pip install pypcap dpkt  # Windows
# OR
pip install scapy  # Universal fallback
```

---

## ✅ Quick Check

To verify all required libraries are installed:

```bash
python -c "
import numpy
import pandas
import sklearn
import tensorflow
import joblib
import flask
import requests
print('✅ All core libraries installed!')
"
```

---

## 📝 Notes

1. **TensorFlow**: Use `tensorflow-cpu` if you don't have a GPU. For Python 3.13, you may need TensorFlow 2.20+ or use Python 3.11 with TensorFlow 2.17.

2. **Packet Capture**: 
   - **pypcap** (Windows) is fastest but requires Npcap installation
   - **tcpdump** (Linux) is fastest and usually pre-installed
   - **scapy** is universal but slower (good fallback)

3. **Google Colab**: If training on Google Colab, TensorFlow and most libraries are pre-installed. You may need to install `joblib`:
   ```python
   !pip install joblib
   ```






