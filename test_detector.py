import numpy as np
import joblib
import time
from pathlib import Path
import tensorflow as tf

# Import project config
from feature_config import FEATURE_COLUMNS, load_feature_metadata
from realtime_transformer_detector import (
    build_model_architecture,
    MODEL_PATH,
    SCALER_PATH,
    SEQ_LEN,
)

# Load feature order used by the model
feature_order = list(load_feature_metadata(Path(__file__).parent / "feature_columns.json"))
n_features = len(feature_order)

# ----------------------------------------------------------
# Helper: Build fake 1-second window with chosen parameters
# ----------------------------------------------------------
def make_fake_window(
    packet_count,
    byte_count,
    avg_size,
    std_size,
    unique_src,
    unique_dst,
    tcp_c,
    udp_c,
    icmp_c,
    duration_sec=1.0,
):
    feature_map = {
        "packet_count": packet_count,
        "byte_count": byte_count,
        "avg_pkt_size": avg_size,
        "std_pkt_size": std_size,
        "duration_sec": duration_sec,
        "unique_src_ips": unique_src,
        "unique_dst_ips": unique_dst,
        "tcp_count": tcp_c,
        "udp_count": udp_c,
        "icmp_count": icmp_c,
    }

    vec = np.array([feature_map.get(col, 0.0) for col in feature_order], dtype=float)
    return vec


# ----------------------------------------------------------
# Load model + scaler
# ----------------------------------------------------------
print("[*] Loading model and scaler...")

# Try direct load; fallback to architecture rebuild
try:
    model = tf.keras.models.load_model(str(MODEL_PATH), compile=False, safe_mode=False)
except:
    print("[!] Direct load failed. Rebuilding model architecture...")
    model = build_model_architecture((SEQ_LEN, n_features))
    model.load_weights(str(MODEL_PATH))

scaler = joblib.load(str(SCALER_PATH))

print("[*] Model ready.")
print(f"[*] SEQ_LEN = {SEQ_LEN}, Features = {n_features}")

# ----------------------------------------------------------
# Create scenarios
# ----------------------------------------------------------

def generate_benign_sequence():
    """
    Benign traffic:
    - low packets
    - few sources
    - stable sizes
    """
    seq = []
    for _ in range(SEQ_LEN):
        vec = make_fake_window(
            packet_count=np.random.randint(20, 80),
            byte_count=np.random.randint(5_000, 30_000),
            avg_size=np.random.uniform(200, 600),
            std_size=np.random.uniform(10, 80),
            unique_src=np.random.randint(1, 5),
            unique_dst=np.random.randint(1, 4),
            tcp_c=np.random.randint(10, 60),
            udp_c=np.random.randint(5, 20),
            icmp_c=np.random.randint(0, 3),
        )
        seq.append(vec)
    return np.stack(seq)


def generate_ddos_sequence():
    """
    DDoS attack simulation:
    - extremely high packet rate
    - many unique sources
    - large bursts of bytes
    """
    seq = []
    for _ in range(SEQ_LEN):
        vec = make_fake_window(
            packet_count=np.random.randint(2000, 6000),
            byte_count=np.random.randint(3_000_000, 9_000_000),
            avg_size=np.random.uniform(600, 1200),
            std_size=np.random.uniform(80, 200),
            unique_src=np.random.randint(50, 300),
            unique_dst=np.random.randint(1, 5),
            tcp_c=np.random.randint(1000, 5000),
            udp_c=np.random.randint(200, 600),
            icmp_c=np.random.randint(50, 300),
        )
        seq.append(vec)
    return np.stack(seq)


# ----------------------------------------------------------
# Predict helper
# ----------------------------------------------------------
def run_prediction(seq_data, label):
    flat = seq_data.reshape(-1, seq_data.shape[-1])
    scaled = scaler.transform(flat).reshape(1, SEQ_LEN, seq_data.shape[-1])

    pred = float(model.predict(scaled, verbose=0)[0][0])
    print(f"\n=== RESULT ({label}) ===")
    print(f"Score: {pred:.4f}")
    print("Attack Detected" if pred >= 0.5 else "Benign traffic")


def generate_mixed_sequence():
    """
    Mixed traffic pattern:
    - Combines benign and semi-malicious bursts.
    - Some windows look normal, others show suspicious spikes.
    - Very realistic for enterprise networks.
    """
    seq = []

    for i in range(SEQ_LEN):
        # 70% chance of normal traffic, 30% chance of burst
        if np.random.rand() < 0.7:
            # benign window
            vec = make_fake_window(
                packet_count=np.random.randint(30, 120),
                byte_count=np.random.randint(10_000, 80_000),
                avg_size=np.random.uniform(200, 600),
                std_size=np.random.uniform(10, 100),
                unique_src=np.random.randint(1, 10),
                unique_dst=np.random.randint(1, 6),
                tcp_c=np.random.randint(20, 80),
                udp_c=np.random.randint(10, 30),
                icmp_c=np.random.randint(0, 5),
            )
        else:
            # suspicious burst (but not full DDoS)
            vec = make_fake_window(
                packet_count=np.random.randint(500, 1800),
                byte_count=np.random.randint(300_000, 1_500_000),
                avg_size=np.random.uniform(400, 900),
                std_size=np.random.uniform(50, 150),
                unique_src=np.random.randint(15, 80),
                unique_dst=np.random.randint(1, 5),
                tcp_c=np.random.randint(200, 1200),
                udp_c=np.random.randint(40, 200),
                icmp_c=np.random.randint(5, 50),
            )

        seq.append(vec)

    return np.stack(seq)


# ----------------------------------------------------------
# RUN TESTS
# ----------------------------------------------------------
if __name__ == "__main__":
    print("\n[*] Generating benign traffic test...")
    benign = generate_benign_sequence()
    run_prediction(benign, "Benign Traffic")

    print("\n[*] Generating DDoS attack test...")
    ddos = generate_ddos_sequence()
    run_prediction(ddos, "Simulated DDoS Attack")

    print("\n[*] Finished.")

    print("\n[*] Generating mixed traffic pattern test...")
    mixed = generate_mixed_sequence()
    run_prediction(mixed, "Mixed Traffic Pattern")

    print("\n[*] Finished.")

