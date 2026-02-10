"""Waveform test script for the dashboard.

Sends a stream of 'normal' and 'abnormal' updates to `/api/update` so the
dashboard shows a pulsing / ECG-like spike. The script defaults to
`http://127.0.0.1:5000` but can be pointed to another host with
`DASH_HOST` environment variable.

Usage:
  python test_post_to_dashboard.py  # runs 120 updates by default
"""
import os
import time
import math
import random
import requests

HOST = os.getenv('DASH_HOST', 'http://127.0.0.1:5000')
URL = HOST.rstrip('/') + '/api/update'

def make_payload(score, attack, packets, bytes_, features_extra=None):
    features = {
        'packet_count': packets,
        'byte_count': bytes_,
        'avg_pkt_size': (bytes_ / packets) if packets else 0,
        'std_pkt_size': random.uniform(1, 10),
        'duration_sec': 1.0,
        'unique_src_ips': random.randint(1, 5),
        'unique_dst_ips': random.randint(1, 3),
        'tcp_count': int(packets * 0.6),
        'udp_count': int(packets * 0.35),
        'icmp_count': 0,
    }
    if features_extra:
        features.update(features_extra)
    return {
        'score': score,
        'attack': attack,
        'features': features
    }

def run_waveform(duration_seconds=60, interval=0.5):
    steps = int(duration_seconds / interval)
    t0 = time.time()
    for i in range(steps):
        # base sinusoidal / pulse for 'normal' traffic
        phase = (time.time() - t0) * 2 * math.pi * 0.5  # 0.5 Hz baseline
        base = 20 + 6 * math.sin(phase) + random.uniform(-2, 2)

        # every few seconds create a short spike (simulating attack pulse)
        spike = 0
        attack = False
        score = 0.0
        if (i % 20) in (0, 1):
            spike = random.randint(200, 800)
            attack = True
            score = min(1.0, 0.6 + random.random() * 0.4)

        packets = max(0, int(base + spike))
        bytes_ = packets * random.randint(60, 800)

        payload = make_payload(score=score, attack=attack, packets=packets, bytes_=bytes_)

        try:
            r = requests.post(URL, json=payload, timeout=1.0)
            print(f'[{i}/{steps}] posted packets={packets} attack={attack} score={score:.2f} -> {r.status_code}')
        except Exception as e:
            print('POST failed:', e)

        time.sleep(interval)

if __name__ == '__main__':
    # Default: 60s at 0.5s interval => 120 updates
    run_waveform(duration_seconds=60, interval=0.5)
