#!/usr/bin/env python3
"""
this script should run in the local machine (pfSense firewall or IDS)

realtime_transformer_detector.py
Supports:
 - live packet capture (scapy/tcpdump)
 - real-time pfSense filter.log tailing (clog -f or tail -F)
Aggregates 1-second windows, keeps last `SEQ_LEN` windows, predicts with saved model.
"""

import time
import threading
import subprocess
from collections import deque, Counter
import queue
import os
import sys
import json
from pathlib import Path

import numpy as np
import joblib
import tensorflow as tf
from tensorflow import keras

from feature_config import FEATURE_COLUMNS, load_feature_metadata

# ----------------------------
# Model architecture (must match training)
# ----------------------------


def build_model_architecture(input_shape):
    """Rebuild the model architecture to match training."""
    from tensorflow.keras import layers

    inputs = layers.Input(shape=input_shape)
    attn = layers.MultiHeadAttention(
        num_heads=4, key_dim=input_shape[-1])(inputs, inputs)
    attn = layers.LayerNormalization(epsilon=1e-6)(inputs + attn)
    ffn = layers.Dense(64, activation="relu")(attn)
    ffn = layers.Dense(input_shape[-1])(ffn)
    x = layers.LayerNormalization(epsilon=1e-6)(attn + ffn)
    x = layers.GlobalAveragePooling1D()(x)
    x = layers.Dense(64, activation="relu")(x)
    outputs = layers.Dense(1, activation="sigmoid")(x)
    model = tf.keras.Model(inputs=inputs, outputs=outputs)
    return model


# ----------------------------
# CONFIG
# ----------------------------
ROOT = Path(__file__).resolve().parent
MODEL_PATH = ROOT / "ddos_transformer.h5"  # path to your trained Transformer
SCALER_PATH = ROOT / "scaler.gz"  # path to your saved scaler (joblib)
FEATURE_META_PATH = ROOT / "feature_columns.json"
# number of 1-sec windows per sequence (same window used in training)
SEQ_LEN = 10
WINDOW_SEC = 1.0  # aggregation window duration in seconds
PRED_THRESHOLD = 0.5  # threshold for attack detection
LOG_FILE = "ddos_alerts.log"  # where to write alerts

# Choose which inputs to enable
ENABLE_SNIF = True  # live interface sniffing via scapy/tcpdump
# pfSense log tailing (clog -f /var/log/filter.log) or tail -F
ENABLE_PFSENSE = False

# If sniffing, set interface (e.g., "eth0", "ens3"). If None, scapy chooses default
SNIFF_IFACE = "VMware Network Adapter VMnet8"

# pfSense log command (change if not using clog)
# or: ["tail", "-F", "/path/to/filter.log"]
PFSENSE_LOG_CMD = ["clog", "-f", "/var/log/filter.log"]

# ----------------------------
# Helper: feature aggregation per 1-second window
# ----------------------------
FEATURE_ORDER = list(load_feature_metadata(FEATURE_META_PATH))
if len(FEATURE_ORDER) != len(FEATURE_COLUMNS):
    print(
        f"Feature count mismatch between config ({len(FEATURE_ORDER)}) and code ({len(FEATURE_COLUMNS)}). "
        "Using on-disk order.",
        file=sys.stderr,
    )


def make_window_feature(packet_stats):
    """
    Input: packet_stats from last WINDOW_SEC (dict)
    Output: 1D numpy array of features (order must match training)
    Features chosen here (example):
      - packet_count
      - byte_count
      - avg_pkt_size
      - std_pkt_size
      - duration (in seconds)  (if 0 -> small epsilon)
      - unique_src_ips
      - unique_dst_ips
      - tcp_count
      - udp_count
      - icmp_count
    Adjust this list to match the features you used during training.
    """
    pc = packet_stats["count"]
    bc = packet_stats["bytes"]
    sizes = packet_stats["sizes"]
    duration = max(packet_stats["last_ts"] - packet_stats["first_ts"], 1e-6)
    avg_size = float(np.mean(sizes)) if sizes else 0.0
    std_size = float(np.std(sizes)) if sizes else 0.0
    uniq_src = len(packet_stats["srcs"])
    uniq_dst = len(packet_stats["dsts"])
    proto_counts = packet_stats["protos"]
    tcp_c = proto_counts.get("TCP", 0)
    udp_c = proto_counts.get("UDP", 0)
    icmp_c = proto_counts.get("ICMP", 0)

    feature_map = {
        "packet_count": pc,
        "byte_count": bc,
        "avg_pkt_size": avg_size,
        "std_pkt_size": std_size,
        "duration_sec": duration,
        "unique_src_ips": float(uniq_src),
        "unique_dst_ips": float(uniq_dst),
        "tcp_count": float(tcp_c),
        "udp_count": float(udp_c),
        "icmp_count": float(icmp_c),
    }

    feat = np.array([feature_map.get(col, 0.0)
                    for col in FEATURE_ORDER], dtype=float)
    return feat


# ----------------------------
# Helper: Build packet stats from buffer
# ----------------------------
def build_packet_stats_from_buffer(buf, now):
    """Build packet_stats dictionary from buffer of (ts, length, src, dst, proto) tuples."""
    if buf:
        srcs = set()
        dsts = set()
        protos = Counter()
        sizes = []
        total_bytes = 0
        times = []

        for (ts, length, src, dst, proto) in buf:
            times.append(ts)
            sizes.append(length)
            total_bytes += length
            if src:
                srcs.add(src)
            if dst:
                dsts.add(dst)
            protos[proto] += 1

        return {
            "count": len(buf),
            "bytes": total_bytes,
            "sizes": sizes,
            "first_ts": min(times) if times else now,
            "last_ts": max(times) if times else now,
            "srcs": srcs,
            "dsts": dsts,
            "protos": protos,
        }
    else:
        return {
            "count": 0, "bytes": 0, "sizes": [],
            "first_ts": now, "last_ts": now,
            "srcs": set(), "dsts": set(), "protos": Counter()
        }


# ----------------------------
# Packet capture: pypcap (Windows) - HIGH PERFORMANCE
# ----------------------------
def sniffing_worker_pypcap(aggregate_queue, stop_event):
    """
    High-speed packet capture using pypcap (Windows with Npcap).
    Requires: pip install pypcap dpkt
    Also requires Npcap installed: https://nmap.org/npcap/
    """
    try:
        import pcap
        import dpkt
        import socket as socket_lib
    except ImportError as e:
        print(f"pypcap/dpkt not available: {e}", file=sys.stderr)
        print("Install with: pip install pypcap dpkt", file=sys.stderr)
        print("Also install Npcap from: https://nmap.org/npcap/", file=sys.stderr)
        return

    current_buffer = deque(maxlen=100000)
    buffer_lock = threading.Lock()
    last_flush = time.time()
    packet_count = 0

    try:
        # Open interface for capture
        iface = SNIFF_IFACE if SNIFF_IFACE else None
        pc = pcap.pcap(name=iface, promisc=True, immediate=True)

        print(f"pypcap capture started on: {pc.name}")

        while not stop_event.is_set():
            try:
                # Capture packets with timeout
                ts, pkt = pc.next()
                if pkt is None:
                    time.sleep(0.001)
                    continue

                length = len(pkt)
                src = None
                dst = None
                proto = "OTHER"

                # Fast parsing with dpkt
                try:
                    eth = dpkt.ethernet.Ethernet(pkt)
                    if isinstance(eth.data, dpkt.ip.IP):
                        ip = eth.data
                        src = socket_lib.inet_ntoa(ip.src)
                        dst = socket_lib.inet_ntoa(ip.dst)

                        if isinstance(ip.data, dpkt.tcp.TCP):
                            proto = "TCP"
                        elif isinstance(ip.data, dpkt.udp.UDP):
                            proto = "UDP"
                        elif isinstance(ip.data, dpkt.icmp.ICMP):
                            proto = "ICMP"
                    elif isinstance(eth.data, dpkt.ip6.IP6):
                        ip6 = eth.data
                        src = socket_lib.inet_ntop(
                            socket_lib.AF_INET6, ip6.src)
                        dst = socket_lib.inet_ntop(
                            socket_lib.AF_INET6, ip6.dst)
                        # IPv6 protocol check
                        if ip6.nxt == 6:  # TCP
                            proto = "TCP"
                        elif ip6.nxt == 17:  # UDP
                            proto = "UDP"
                        elif ip6.nxt == 58:  # ICMPv6
                            proto = "ICMP"
                except:
                    pass  # Skip non-IP packets

                with buffer_lock:
                    current_buffer.append((ts, length, src, dst, proto))
                    packet_count += 1

            except Exception:
                continue

            # Flush window
            now = time.time()
            if now - last_flush >= WINDOW_SEC:
                with buffer_lock:
                    if len(current_buffer) == 0:
                        last_flush = now
                        continue
                    buf = list(current_buffer)
                    current_buffer.clear()
                    local_count = packet_count
                    packet_count = 0
                last_flush = now

                packet_stats = build_packet_stats_from_buffer(buf, now)
                feat = make_window_feature(packet_stats)
                aggregate_queue.put(("sniff", feat))

                if local_count > 0:
                    print(
                        f"Captured {local_count} packets (pypcap)", flush=True)

    except Exception as e:
        print(f"pypcap error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()


# ----------------------------
# Packet capture: tcpdump (Linux) - HIGH PERFORMANCE
# ----------------------------
def sniffing_worker_tcpdump(aggregate_queue, stop_event):
    """
    High-speed packet capture using tcpdump (Linux).
    Requires: tcpdump installed (usually pre-installed on Linux)
    """
    import re
    import socket as socket_lib

    current_buffer = deque(maxlen=100000)
    buffer_lock = threading.Lock()
    last_flush = time.time()
    packet_count = 0

    # Build tcpdump command
    tcpdump_cmd = ["tcpdump", "-n", "-l", "-q", "-tttt"]
    if SNIFF_IFACE:
        tcpdump_cmd.extend(["-i", SNIFF_IFACE])
    # Output format: timestamp IP src > dst: flags ... length N
    tcpdump_cmd.append("ip or ip6")

    try:
        proc = subprocess.Popen(
            tcpdump_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
        print(
            f"tcpdump capture started on: {SNIFF_IFACE or 'default interface'}")

        # Regex patterns for parsing tcpdump output
        # Example: 2024-01-01 12:00:00.123456 IP 192.168.1.1.80 > 192.168.1.2.12345: Flags [P.], seq 1:100, ack 1, length 99
        ip_pattern = re.compile(
            r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+IP\s+(\S+)\s+>\s+(\S+):.*length\s+(\d+)'
        )
        ip6_pattern = re.compile(
            r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+IP6\s+(\S+)\s+>\s+(\S+):.*length\s+(\d+)'
        )
        proto_pattern = re.compile(r'\b(TCP|UDP|ICMP|ICMP6)\b')

        while not stop_event.is_set():
            try:
                line = proc.stdout.readline()
                if not line:
                    if proc.poll() is not None:
                        break
                    time.sleep(0.01)
                    continue

                # Parse tcpdump line
                ts_str = None
                src = None
                dst = None
                length = 0
                proto = "OTHER"

                # Try IPv4 pattern first
                match = ip_pattern.search(line)
                if match:
                    ts_str, src_full, dst_full, length_str = match.groups()
                    # Extract IP from "ip.port" format
                    src = src_full.split(
                        '.')[0] if '.' in src_full else src_full.split(':')[0]
                    dst = dst_full.split(
                        '.')[0] if '.' in dst_full else dst_full.split(':')[0]
                    length = int(length_str)
                else:
                    # Try IPv6 pattern
                    match = ip6_pattern.search(line)
                    if match:
                        ts_str, src_full, dst_full, length_str = match.groups()
                        src = src_full.split(
                            '.')[0] if '.' in src_full else src_full.split(':')[0]
                        dst = dst_full.split(
                            '.')[0] if '.' in dst_full else dst_full.split(':')[0]
                        length = int(length_str)

                # Determine protocol
                proto_match = proto_pattern.search(line)
                if proto_match:
                    proto_str = proto_match.group(1).upper()
                    if proto_str in ["TCP", "UDP", "ICMP"]:
                        proto = proto_str
                    elif proto_str == "ICMP6":
                        proto = "ICMP"

                # Parse timestamp
                try:
                    if ts_str:
                        # Parse tcpdump timestamp format
                        from datetime import datetime
                        dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S.%f")
                        ts = dt.timestamp()
                    else:
                        ts = time.time()
                except:
                    ts = time.time()

                with buffer_lock:
                    current_buffer.append((ts, length, src, dst, proto))
                    packet_count += 1

            except Exception:
                continue

            # Flush window
            now = time.time()
            if now - last_flush >= WINDOW_SEC:
                with buffer_lock:
                    if len(current_buffer) == 0:
                        last_flush = now
                        continue
                    buf = list(current_buffer)
                    current_buffer.clear()
                    local_count = packet_count
                    packet_count = 0
                last_flush = now

                packet_stats = build_packet_stats_from_buffer(buf, now)
                feat = make_window_feature(packet_stats)
                aggregate_queue.put(("sniff", feat))

                if local_count > 0:
                    print(
                        f"Captured {local_count} packets (tcpdump)", flush=True)

    except FileNotFoundError:
        print("ERROR: tcpdump not found. Install with: sudo apt-get install tcpdump", file=sys.stderr)
    except Exception as e:
        print(f"tcpdump error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
    finally:
        try:
            if 'proc' in locals():
                proc.terminate()
                proc.wait(timeout=2)
        except:
            pass


# ----------------------------
# Packet capture thread (scapy) - FALLBACK
# ----------------------------
def sniffing_worker_scapy(aggregate_queue, stop_event):
    """
    Collect packets for WINDOW_SEC intervals, build packet_stats, send to aggregate_queue as feature vectors.
    Optimized for high-speed packet capture.
    """
    try:
        from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP
        from scapy.arch import get_if_list
    except Exception as e:
        print("scapy import error:", e, file=sys.stderr)
        return

    # Use deque for thread-safe, high-performance buffer
    from collections import deque as deque_collection
    current_buffer = deque_collection(maxlen=100000)  # Prevent memory issues
    buffer_lock = threading.Lock()
    last_flush = time.time()
    packet_count = 0

    def pkt_handler(pkt):
        # Ultra-fast packet handler - minimize operations
        nonlocal packet_count
        try:
            # Fast timestamp and length extraction
            ts = pkt.time if hasattr(pkt, 'time') else time.time()
            length = len(pkt)

            # Optimized layer checking - check most common first
            # Use direct attribute access instead of haslayer() when possible
            src = None
            dst = None
            proto = "OTHER"

            # Fast path: check IP layer directly
            ip_layer = pkt.getlayer(IP)
            if ip_layer is not None:
                src = ip_layer.src
                dst = ip_layer.dst
                # Check transport layer
                if pkt.haslayer(TCP):
                    proto = "TCP"
                elif pkt.haslayer(UDP):
                    proto = "UDP"
                elif pkt.haslayer(ICMP):
                    proto = "ICMP"
            else:
                # Check IPv6
                ipv6_layer = pkt.getlayer(IPv6)
                if ipv6_layer is not None:
                    src = ipv6_layer.src
                    dst = ipv6_layer.dst
                    if pkt.haslayer(TCP):
                        proto = "TCP"
                    elif pkt.haslayer(UDP):
                        proto = "UDP"
                    elif pkt.haslayer(ICMP):
                        proto = "ICMP"

            # Append without lock if possible (deque is thread-safe for append)
            # But we'll use lock for safety with high-speed capture
            with buffer_lock:
                current_buffer.append((ts, length, src, dst, proto))
                packet_count += 1
        except:
            # Silently skip malformed packets - no exception handling overhead
            pass

    # Optimized sniff parameters for performance
    sniff_kwargs = {
        "prn": pkt_handler,
        "store": False,  # Don't store packets - saves memory
        "stop_filter": lambda x: stop_event.is_set(),  # Allow clean stop
    }

    if SNIFF_IFACE:
        sniff_kwargs["iface"] = SNIFF_IFACE

    # Start sniff in a separate thread (non-blocking)
    sniff_thread = threading.Thread(
        target=lambda: sniff(**sniff_kwargs), daemon=True)
    sniff_thread.start()
    print(f"Sniffing thread started on interface: {SNIFF_IFACE or 'default'}")

    try:
        while not stop_event.is_set():
            # Reduced sleep time for faster response
            time.sleep(0.1)  # Check every 50ms instead of 100ms
            now = time.time()
            if now - last_flush >= WINDOW_SEC:
                # Fast buffer swap
                with buffer_lock:
                    if len(current_buffer) == 0:
                        last_flush = now
                        continue
                    # Convert to list for faster iteration
                    buf = list(current_buffer)
                    current_buffer.clear()
                    local_count = packet_count
                    packet_count = 0
                last_flush = now

                # Build packet stats
                packet_stats = build_packet_stats_from_buffer(buf, now)

                feat = make_window_feature(packet_stats)
                aggregate_queue.put(("sniff", feat))

                if local_count > 0:
                    print(
                        f"Captured {local_count} packets (scapy)", flush=True)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"Scapy sniffing error: {e}", file=sys.stderr)


# ----------------------------
# Main sniffing worker - OS detection and method selection
# ----------------------------
def sniffing_worker(aggregate_queue, stop_event):
    """
    Main sniffing worker that selects the best capture method based on OS.
    - Windows: Uses pypcap (requires Npcap)
    - Linux: Uses tcpdump
    - Fallback: Uses scapy
    """
    # Detect OS and try appropriate method
    if sys.platform == 'win32':
        # Windows: Try pypcap first
        try:
            import pcap
            print("Using pypcap (Windows/Npcap) for high-speed capture")
            sniffing_worker_pypcap(aggregate_queue, stop_event)
            return
        except ImportError:
            print("pypcap not available, falling back to scapy", file=sys.stderr)
            print(
                "For better performance, install: pip install pypcap dpkt", file=sys.stderr)
            print("And install Npcap from: https://nmap.org/npcap/", file=sys.stderr)
            sniffing_worker_scapy(aggregate_queue, stop_event)
            return

    elif sys.platform.startswith('linux'):
        # Linux: Try tcpdump first
        try:
            # Check if tcpdump is available
            result = subprocess.run(
                ["which", "tcpdump"],
                capture_output=True,
                text=True,
                timeout=1
            )
            if result.returncode == 0:
                print("Using tcpdump (Linux) for high-speed capture")
                sniffing_worker_tcpdump(aggregate_queue, stop_event)
                return
            else:
                print("tcpdump not found, falling back to scapy", file=sys.stderr)
                print("Install with: sudo apt-get install tcpdump", file=sys.stderr)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            print("tcpdump check failed, falling back to scapy", file=sys.stderr)

        # Fallback to scapy
        sniffing_worker_scapy(aggregate_queue, stop_event)
        return

    else:
        # Other OS: Use scapy
        print(f"Unknown OS ({sys.platform}), using scapy", file=sys.stderr)
        sniffing_worker_scapy(aggregate_queue, stop_event)
        return


# ----------------------------
# pfSense log tail worker
# ----------------------------
def pfsense_worker(aggregate_queue, stop_event):
    """
    Tail pfSense filter.log in real-time (via clog -f or tail -F).
    Parse each line minimally to extract timestamp, src_ip, dst_ip, proto, size.
    Aggregate same as sniffing_worker into 1-second windows.
    """
    try:
        proc = subprocess.Popen(
            PFSENSE_LOG_CMD, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except Exception as e:
        print("Failed to start pfSense log command:", e, file=sys.stderr)
        return

    packet_stats = {"count": 0, "bytes": 0, "sizes": [], "first_ts": 0.0, "last_ts": 0.0, "srcs": set(), "dsts": set(),
                    "protos": Counter()}
    window_start = time.time()

    def flush_window():
        nonlocal packet_stats, window_start
        feat = make_window_feature(packet_stats)
        aggregate_queue.put(("pfsense", feat))
        # reset
        packet_stats = {"count": 0, "bytes": 0, "sizes": [], "first_ts": 0.0, "last_ts": 0.0, "srcs": set(),
                        "dsts": set(), "protos": Counter()}
        window_start = time.time()

    try:
        while not stop_event.is_set():
            line = proc.stdout.readline()
            if not line:
                if proc.poll() is not None:
                    break
                time.sleep(0.01)
                continue
            # Parse pfSense filter.log line - minimal/robust parsing:
            # Example - many pfSense lines have patterns: <timestamp> <host> filterlog: ... SRC=1.2.3.4 DST=5.6.7.8 PROTO=TCP LENGTH=60 ...
            # We'll extract tokens like SRC=, DST=, PROTO=, LENGTH=
            ts = time.time()
            src = None
            dst = None
            proto = None
            length = None
            parts = line.strip().split()
            for tok in parts:
                if tok.startswith("SRC="):
                    src = tok.split("SRC=")[-1]
                elif tok.startswith("DST="):
                    dst = tok.split("DST=")[-1]
                elif tok.startswith("PROTO="):
                    proto = tok.split("PROTO=")[-1].upper()
                elif tok.startswith("LENGTH=") or tok.startswith("LEN="):
                    try:
                        length = int(tok.split("=")[-1])
                    except:
                        length = None

            if length is None:
                length = 0
            # Update packet_stats
            if packet_stats["count"] == 0:
                packet_stats["first_ts"] = ts
            packet_stats["last_ts"] = ts
            packet_stats["count"] += 1
            packet_stats["bytes"] += length
            packet_stats["sizes"].append(length)
            if src:
                packet_stats["srcs"].add(src)
            if dst:
                packet_stats["dsts"].add(dst)
            if proto:
                if proto.startswith("TCP"):
                    packet_stats["protos"]["TCP"] += 1
                elif proto.startswith("UDP"):
                    packet_stats["protos"]["UDP"] += 1
                elif proto.startswith("ICMP"):
                    packet_stats["protos"]["ICMP"] += 1
                else:
                    packet_stats["protos"]["OTHER"] += 1

            # flush every WINDOW_SEC
            if time.time() - window_start >= WINDOW_SEC:
                flush_window()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            proc.terminate()
        except:
            pass


# ----------------------------
# Aggregator & Predictor
# ----------------------------
def predictor_worker(aggregate_queue, stop_event):
    # load model & scaler
    if not MODEL_PATH.exists() or not SCALER_PATH.exists():
        print("Model or scaler not found. Set MODEL_PATH and SCALER_PATH correctly.", file=sys.stderr)
        stop_event.set()
        return

    # Load model - handle Keras 2.x -> 3.x compatibility issue
    # If direct load fails, rebuild architecture and load weights
    try:
        # Try standard load first
        model = keras.models.load_model(
            str(MODEL_PATH),
            compile=False,
            safe_mode=False
        )
    except Exception as e:
        # If that fails, rebuild architecture and load weights separately
        print(
            f"Warning: Direct load failed ({type(e).__name__}), rebuilding architecture and loading weights...", file=sys.stderr)
        try:
            # Rebuild the model architecture
            n_features = len(FEATURE_ORDER)
            model = build_model_architecture((SEQ_LEN, n_features))
            # Load weights from the saved model file
            model.load_weights(str(MODEL_PATH))
            print("Model loaded successfully using weights-only method.",
                  file=sys.stderr)
        except Exception as e2:
            print(f"Error loading model: {e2}", file=sys.stderr)
            import traceback
            traceback.print_exc()
            stop_event.set()
            return

    scaler = joblib.load(str(SCALER_PATH))

    seq_deque = deque(maxlen=SEQ_LEN)
    seq_features = None

    with open(LOG_FILE, "a") as logf:
        while not stop_event.is_set():
            try:
                source, feat = aggregate_queue.get(timeout=1.0)
            except queue.Empty:
                continue
            # feat: 1D numpy array of raw features for the last WINDOW_SEC
            seq_deque.append(feat)
            # When we have SEQ_LEN windows, build input
            if len(seq_deque) == SEQ_LEN:
                # shape (SEQ_LEN, n_features)
                X = np.stack(list(seq_deque), axis=0)
                # scale: scaler expects 2D samples; we flatten then inverse later
                # shape (SEQ_LEN, n_features)
                flat = X.reshape(-1, X.shape[-1])
                scaled_flat = scaler.transform(flat)
                scaled_seq = scaled_flat.reshape(
                    1, SEQ_LEN, X.shape[-1])  # batch dim
                # predict
                pred = float(model.predict(scaled_seq, verbose=0)[0][0])

                # log & alert in the dashboard
                import requests

                feature_payload = {col: float(val) for col, val in zip(
                    FEATURE_ORDER, feat.tolist())}
                payload = {
                    "score": pred,
                    "attack": pred >= PRED_THRESHOLD,
                    "features": feature_payload,
                    "feature_order": FEATURE_ORDER,
                }

                try:
                    requests.post("http://127.0.0.1:5000/api/update",
                                  json=payload, timeout=0.2)
                except:
                    pass

                ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                if pred >= PRED_THRESHOLD:
                    msg = f"{ts} ALERT: DDoS suspected (score={pred:.4f}) from source={source}"
                    print(msg)
                    logf.write(msg + "\n")
                    logf.flush()
                else:
                    # optional: print normal score occasionally
                    print(f"{ts} OK score={pred:.4f}")
            # allow other tasks
            time.sleep(0.001)


# ----------------------------
# Main: start threads
# ----------------------------
def main():
    aggregate_queue = queue.Queue(maxsize=1000)
    stop_event = threading.Event()

    threads = []

    if ENABLE_SNIF:
        t_sniff = threading.Thread(target=sniffing_worker, args=(
            aggregate_queue, stop_event), daemon=True)
        threads.append(t_sniff)
        t_sniff.start()

    if ENABLE_PFSENSE:
        t_pfs = threading.Thread(target=pfsense_worker, args=(
            aggregate_queue, stop_event), daemon=True)
        threads.append(t_pfs)
        t_pfs.start()

    t_pred = threading.Thread(target=predictor_worker, args=(
        aggregate_queue, stop_event), daemon=True)
    threads.append(t_pred)
    t_pred.start()

    print("Real-time detector started. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping...")
        stop_event.set()
        time.sleep(1)


if __name__ == "__main__":
    main()
