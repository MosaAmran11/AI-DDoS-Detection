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

from feature_config import load_feature_metadata, KDD_COLUMNS, CATEGORICAL_COLUMNS

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
MODEL_PATH = ROOT / "model" / "ddos_transformer.h5"  # path to your trained Transformer
SCALER_PATH = ROOT / "model" / "scaler.gz"  # path to your saved scaler (joblib)
FEATURE_META_PATH = ROOT / "model" / "feature_columns.json"
# number of 1-sec windows per sequence (same window used in training)
SEQ_LEN = 10
WINDOW_SEC = 1.0  # aggregation window duration in seconds
PRED_THRESHOLD = 0.5  # threshold for attack detection
LOG_FILE = "ddos_alerts.log"  # where to write alerts

# Choose which inputs to enable
ENABLE_SNIF = True  # live interface sniffing via scapy/tcpdump

# If sniffing, set interface (e.g., "eth0", "ens3"). If None, scapy chooses default
SNIFF_IFACE = "Wi-Fi"

# ----------------------------
# Helper: feature aggregation per 1-second window
# ----------------------------
FEATURE_ORDER = load_feature_metadata(FEATURE_META_PATH)
if not FEATURE_ORDER:
    print(
        f"Warning: No feature metadata found at {FEATURE_META_PATH}. "
        "Please train the model first to generate feature_columns.json",
        file=sys.stderr,
    )
    sys.exit(1)

print(f"Loaded {len(FEATURE_ORDER)} features from training: {FEATURE_ORDER}")


def make_window_feature(packet_stats):
    """
    Input: packet_stats from last WINDOW_SEC (dict)
    Output: 1D numpy array of features (order must match training)
    Maps packet-level statistics to KDD-style features.
    """
    pc = packet_stats["count"]
    bc = packet_stats["bytes"]
    src_bytes = packet_stats.get("src_bytes", 0)
    dst_bytes = packet_stats.get("dst_bytes", 0)
    sizes = packet_stats["sizes"]
    duration = max(packet_stats["last_ts"] - packet_stats["first_ts"], 1e-6)
    uniq_src = len(packet_stats["srcs"])
    uniq_dst = len(packet_stats["dsts"])
    proto_counts = packet_stats["protos"]
    tcp_c = proto_counts.get("TCP", 0)
    udp_c = proto_counts.get("UDP", 0)
    icmp_c = proto_counts.get("ICMP", 0)

    # KDD-style features
    num_flows = packet_stats.get("num_flows", 0)
    srv_count = packet_stats.get("srv_count", 0)
    serror_rate = packet_stats.get("serror_rate", 0.0)
    same_srv_rate = packet_stats.get("same_srv_rate", 0.0)

    # Protocol encoding (0=tcp, 1=udp, 2=icmp, 3=other)
    if tcp_c > 0:
        protocol_type = 0  # tcp
    elif udp_c > 0:
        protocol_type = 1  # udp
    elif icmp_c > 0:
        protocol_type = 2  # icmp
    else:
        protocol_type = 3  # other

    # Service estimation (simplified: use port-based heuristics)
    # In real KDD, this is categorical. We'll use a numeric approximation.
    service = 0  # Default to 'other'

    # Flag estimation (simplified)
    flag = 0  # Default

    # Build comprehensive feature map matching KDD columns
    feature_map = {
        "duration": duration,
        "protocol_type": float(protocol_type),
        "service": float(service),
        "flag": float(flag),
        "src_bytes": float(src_bytes),
        "dst_bytes": float(dst_bytes),
        # Land attack (src_ip == dst_ip) - not easily detectable from packets alone
        "land": 0.0,
        "wrong_fragment": 0.0,
        "urgent": 0.0,
        "hot": 0.0,
        "num_failed_logins": 0.0,
        "logged_in": 0.0,
        "num_compromised": 0.0,
        "root_shell": 0.0,
        "su_attempted": 0.0,
        "num_root": 0.0,
        "num_file_creations": 0.0,
        "num_shells": 0.0,
        "num_access_files": 0.0,
        "num_outbound_cmds": 0.0,
        "is_host_login": 0.0,
        "is_guest_login": 0.0,
        "count": float(num_flows),  # Number of connections to the same host
        # Number of connections to the same service
        "srv_count": float(srv_count),
        "serror_rate": serror_rate,
        "srv_serror_rate": serror_rate,  # Simplified
        "rerror_rate": 0.0,
        "srv_rerror_rate": 0.0,
        "same_srv_rate": same_srv_rate,
        "diff_srv_rate": 1.0 - same_srv_rate if same_srv_rate <= 1.0 else 0.0,
        "srv_diff_host_rate": 0.0,
        "dst_host_count": float(uniq_dst),
        "dst_host_srv_count": float(srv_count),
        "dst_host_same_srv_rate": same_srv_rate,
        "dst_host_diff_srv_rate": 1.0 - same_srv_rate if same_srv_rate <= 1.0 else 0.0,
        "dst_host_same_src_port_rate": 0.0,
        "dst_host_srv_diff_host_rate": 0.0,
        "dst_host_serror_rate": serror_rate,
        "dst_host_srv_serror_rate": serror_rate,
        "dst_host_rerror_rate": 0.0,
        "dst_host_srv_rerror_rate": 0.0,
    }

    # Extract features in the order they were selected during training
    feat = np.array([feature_map.get(col, 0.0)
                    for col in FEATURE_ORDER], dtype=float)
    return feat


# ----------------------------
# Helper: Build packet stats from buffer
# ----------------------------
def build_packet_stats_from_buffer(buf, now):
    """
    Build enhanced packet_stats dictionary from buffer of (ts, length, src, dst, proto, src_port, dst_port, flags) tuples.
    Enhanced to support KDD-style feature extraction.
    """
    if buf:
        srcs = set()
        dsts = set()
        protos = Counter()
        sizes = []
        src_bytes = 0
        dst_bytes = 0
        times = []
        flows = {}  # (src_ip, dst_ip, src_port, dst_port, proto) -> flow stats
        error_packets = 0
        tcp_flags = Counter()

        for packet in buf:
            if len(packet) >= 5:
                ts, length, src, dst, proto = packet[0], packet[1], packet[2], packet[3], packet[4]
                src_port = packet[5] if len(packet) > 5 else 0
                dst_port = packet[6] if len(packet) > 6 else 0
                flags = packet[7] if len(packet) > 7 else 0
            else:
                continue

            times.append(ts)
            sizes.append(length)
            if src:
                srcs.add(src)
            if dst:
                dsts.add(dst)
            protos[proto] += 1

            # Track bytes by direction (simplified: assume first packet direction)
            if src and dst:
                # Simple heuristic: if we've seen this flow before, it's likely same direction
                flow_key = (src, dst, src_port, dst_port, proto)
                if flow_key not in flows:
                    flows[flow_key] = {'src_bytes': 0,
                                       'dst_bytes': 0, 'count': 0, 'errors': 0}

                flows[flow_key]['count'] += 1
                # Heuristic: assume packets from src to dst are src_bytes
                if len(flows) % 2 == 0:  # Alternate for simplicity
                    src_bytes += length
                    flows[flow_key]['src_bytes'] += length
                else:
                    dst_bytes += length
                    flows[flow_key]['dst_bytes'] += length

                # Track TCP flags if available
                if flags and proto == "TCP":
                    tcp_flags[flags] += 1
            else:
                src_bytes += length

            # Simple error detection (can be enhanced)
            if length == 0:
                error_packets += 1

        total_bytes = src_bytes + dst_bytes
        num_flows = len(flows)

        # Count unique services (destination IP + destination port combinations)
        services = set()
        for packet in buf:
            if len(packet) >= 7:
                dst = packet[3]
                dst_port = packet[6]
                if dst:
                    services.add((dst, dst_port))
        srv_count = len(services)

        # Compute error rates
        total_packets = len(buf)
        serror_rate = error_packets / \
            max(total_packets, 1) if total_packets > 0 else 0.0

        # Connection statistics - same service rate
        # Count flows with same destination service
        dst_services = {}
        for packet in buf:
            if len(packet) >= 7:
                src = packet[2]
                dst = packet[3]
                dst_port = packet[6]
                if src and dst:
                    service_key = (dst, dst_port)
                    if service_key not in dst_services:
                        dst_services[service_key] = set()
                    dst_services[service_key].add(src)

        # Calculate same service rate
        same_srv_count = sum(
            1 for src_set in dst_services.values() if len(src_set) > 1)
        same_srv_rate = same_srv_count / \
            max(num_flows, 1) if num_flows > 0 else 0.0

        return {
            "count": len(buf),
            "bytes": total_bytes,
            "src_bytes": src_bytes,
            "dst_bytes": dst_bytes,
            "sizes": sizes,
            "first_ts": min(times) if times else now,
            "last_ts": max(times) if times else now,
            "srcs": srcs,
            "dsts": dsts,
            "protos": protos,
            "num_flows": num_flows,
            "srv_count": srv_count,
            "serror_rate": serror_rate,
            "same_srv_rate": same_srv_rate,
            "tcp_flags": tcp_flags,
            "flows": flows,
        }
    else:
        return {
            "count": 0, "bytes": 0, "src_bytes": 0, "dst_bytes": 0, "sizes": [],
            "first_ts": now, "last_ts": now,
            "srcs": set(), "dsts": set(), "protos": Counter(),
            "num_flows": 0, "srv_count": 0, "serror_rate": 0.0,
            "same_srv_rate": 0.0, "tcp_flags": Counter(), "flows": {}
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
                src_port = 0
                dst_port = 0
                flags = 0

                # Fast parsing with dpkt
                try:
                    eth = dpkt.ethernet.Ethernet(pkt)
                    if isinstance(eth.data, dpkt.ip.IP):
                        ip = eth.data
                        src = socket_lib.inet_ntoa(ip.src)
                        dst = socket_lib.inet_ntoa(ip.dst)

                        if isinstance(ip.data, dpkt.tcp.TCP):
                            proto = "TCP"
                            tcp = ip.data
                            src_port = tcp.sport
                            dst_port = tcp.dport
                            flags = tcp.flags
                        elif isinstance(ip.data, dpkt.udp.UDP):
                            proto = "UDP"
                            udp = ip.data
                            src_port = udp.sport
                            dst_port = udp.dport
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
                            try:
                                tcp = dpkt.tcp.TCP(ip6.data)
                                src_port = tcp.sport
                                dst_port = tcp.dport
                                flags = tcp.flags
                            except:
                                pass
                        elif ip6.nxt == 17:  # UDP
                            proto = "UDP"
                            try:
                                udp = dpkt.udp.UDP(ip6.data)
                                src_port = udp.sport
                                dst_port = udp.dport
                            except:
                                pass
                        elif ip6.nxt == 58:  # ICMPv6
                            proto = "ICMP"
                except:
                    pass  # Skip non-IP packets

                with buffer_lock:
                    current_buffer.append(
                        (ts, length, src, dst, proto, src_port, dst_port, flags))
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
                src_port = 0
                dst_port = 0
                length = 0
                proto = "OTHER"
                flags = 0

                # Try IPv4 pattern first
                match = ip_pattern.search(line)
                if match:
                    ts_str, src_full, dst_full, length_str = match.groups()
                    # Extract IP and port from "ip.port" format
                    src_parts = src_full.split('.')
                    if len(src_parts) >= 5:  # IPv4 with port
                        src = '.'.join(src_parts[:4])
                        try:
                            src_port = int(src_parts[4])
                        except:
                            src_port = 0
                    else:
                        src = src_full.split(
                            ':')[0] if ':' in src_full else src_full

                    dst_parts = dst_full.split('.')
                    if len(dst_parts) >= 2:  # Check if port is present
                        # Try to extract port (last part after last dot)
                        try:
                            dst_port = int(dst_parts[-1].split(':')[0])
                            dst = '.'.join(
                                dst_parts[:-1]) if len(dst_parts) > 1 else dst_parts[0]
                        except:
                            dst = dst_full.split(
                                ':')[0] if ':' in dst_full else dst_full
                    else:
                        dst = dst_full.split(
                            ':')[0] if ':' in dst_full else dst_full
                    length = int(length_str)
                else:
                    # Try IPv6 pattern
                    match = ip6_pattern.search(line)
                    if match:
                        ts_str, src_full, dst_full, length_str = match.groups()
                        # IPv6 format: [ipv6]:port or ipv6
                        if '[' in src_full and ']' in src_full:
                            src = src_full.split('[')[1].split(']')[0]
                            port_part = src_full.split(']:')
                            if len(port_part) > 1:
                                try:
                                    src_port = int(port_part[1].split('.')[0])
                                except:
                                    src_port = 0
                        else:
                            src = src_full.split(
                                ':')[0] if ':' in src_full else src_full

                        if '[' in dst_full and ']' in dst_full:
                            dst = dst_full.split('[')[1].split(']')[0]
                            port_part = dst_full.split(']:')
                            if len(port_part) > 1:
                                try:
                                    dst_port = int(port_part[1].split('.')[0])
                                except:
                                    dst_port = 0
                        else:
                            dst = dst_full.split(
                                ':')[0] if ':' in dst_full else dst_full
                        length = int(length_str)

                # Determine protocol
                proto_match = proto_pattern.search(line)
                if proto_match:
                    proto_str = proto_match.group(1).upper()
                    if proto_str in ["TCP", "UDP", "ICMP"]:
                        proto = proto_str
                    elif proto_str == "ICMP6":
                        proto = "ICMP"

                # Try to extract TCP flags from line
                if "Flags" in line:
                    if "[S]" in line or "SYN" in line:
                        flags = 2  # SYN
                    elif "[F]" in line or "FIN" in line:
                        flags = 1  # FIN
                    elif "[P]" in line or "PUSH" in line:
                        flags = 8  # PSH

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
                    current_buffer.append(
                        (ts, length, src, dst, proto, src_port, dst_port, flags))
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
            src_port = 0
            dst_port = 0
            flags = 0

            # Fast path: check IP layer directly
            ip_layer = pkt.getlayer(IP)
            if ip_layer is not None:
                src = ip_layer.src
                dst = ip_layer.dst
                # Check transport layer
                if pkt.haslayer(TCP):
                    proto = "TCP"
                    tcp_layer = pkt.getlayer(TCP)
                    src_port = tcp_layer.sport if hasattr(
                        tcp_layer, 'sport') else 0
                    dst_port = tcp_layer.dport if hasattr(
                        tcp_layer, 'dport') else 0
                    flags = tcp_layer.flags if hasattr(
                        tcp_layer, 'flags') else 0
                elif pkt.haslayer(UDP):
                    proto = "UDP"
                    udp_layer = pkt.getlayer(UDP)
                    src_port = udp_layer.sport if hasattr(
                        udp_layer, 'sport') else 0
                    dst_port = udp_layer.dport if hasattr(
                        udp_layer, 'dport') else 0
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
                        tcp_layer = pkt.getlayer(TCP)
                        src_port = tcp_layer.sport if hasattr(
                            tcp_layer, 'sport') else 0
                        dst_port = tcp_layer.dport if hasattr(
                            tcp_layer, 'dport') else 0
                        flags = tcp_layer.flags if hasattr(
                            tcp_layer, 'flags') else 0
                    elif pkt.haslayer(UDP):
                        proto = "UDP"
                        udp_layer = pkt.getlayer(UDP)
                        src_port = udp_layer.sport if hasattr(
                            udp_layer, 'sport') else 0
                        dst_port = udp_layer.dport if hasattr(
                            udp_layer, 'dport') else 0
                    elif pkt.haslayer(ICMP):
                        proto = "ICMP"

            # Append without lock if possible (deque is thread-safe for append)
            # But we'll use lock for safety with high-speed capture
            with buffer_lock:
                current_buffer.append(
                    (ts, length, src, dst, proto, src_port, dst_port, flags))
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
