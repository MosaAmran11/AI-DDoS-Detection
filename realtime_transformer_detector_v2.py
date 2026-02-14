#!/usr/bin/env python3
"""
realtime_transformer_detector_v2.py

This script is optimized for real-time performance by delegating the 
high-frequency flow tracking and feature aggregation logic to a C++ extension.

The C++ module (flow_agg_cpp) must be compiled and available in the environment.
"""

import time
import threading
import subprocess
from collections import deque
import queue # Still useful for the model prediction queue
import os
import sys
import json
from pathlib import Path

import numpy as np
import joblib
import tensorflow as tf
from tensorflow import keras

# ----------------------------------------------------------------------
# IMPORTANT: C++ Integration Setup
# ----------------------------------------------------------------------
# The C++ files (FlowAggregator.hpp, FlowAggregator.cpp) must be compiled
# into a Python module, assumed here to be named 'flow_agg_cpp', using 
# a tool like pybind11. 
# 
# To allow this script to run without actual C++ compilation for testing,
# we include a Mock class below. For production, DELETE THE MOCK CLASS 
# and uncomment the actual import.
# ----------------------------------------------------------------------

# --- MOCK C++ MODULE (DELETE FOR PRODUCTION) ---
class MockFlowAggregator:
    """Mocks the C++ FlowAggregator class for testing without compilation."""
    def __init__(self, window_ms=1000):
        print("WARNING: Using MOCK C++ Aggregator. Compile C++ code for speed!")
        self.window_ms = window_ms
        self.last_flush_time = int(time.time() * 1000)

    def update_flow(self, flow_id, packet_size, protocol, current_time_ms):
        # In a real C++ implementation, this would update the hash map
        pass

    def check_and_flush_window(self, current_time_ms):
        # In a real C++ implementation, this returns feature vectors on flush
        if current_time_ms > self.last_flush_time + self.window_ms:
            self.last_flush_time = current_time_ms
            # Return dummy data matching the required (BATCH_SIZE, FEATURE_VECTOR_SIZE)
            # which is (1, 10) in this mock example.
            return [list(np.random.rand(10))]
        return []

flow_agg_cpp = sys.modules.get('flow_agg_cpp', None)
if flow_agg_cpp is None:
    class FlowAggregator(MockFlowAggregator): pass
    print("MOCK: Loaded MockFlowAggregator as C++ module not found.")
else:
    # --- REAL C++ MODULE IMPORT (UNCOMMENT FOR PRODUCTION) ---
    from flow_agg_cpp import FlowAggregator
    pass
# ----------------------------------------------------------------------


# --- Global Settings ---
MODEL_PATH = Path('./model/transformer_detector.h5')
SCALER_PATH = Path('./model/scaler.pkl')
LOG_FILE = 'detector_alerts.log'
WINDOW_MS = 1000  # 1 second aggregation window
SEQ_LEN = 30  # Number of historical windows to feed to the Transformer
PRED_THRESHOLD = 0.8  # DDoS detection probability threshold

# Enable/Disable Data Sources (requires appropriate external tools/libraries)
ENABLE_SNIF = False  # Requires Scapy or similar for live capture
ENABLE_PFSENSE = False # Requires SSH/tail access to pfSense filter log
# The sniffing worker typically provides the raw data needed for the C++ object.
# Since we can't run scapy here, we mock the data extraction.

# Placeholder for feature metadata (should be loaded from your config)
FEATURE_COLUMNS = [
    "packet_count", "byte_count", "avg_pkt_size", "std_pkt_size", "duration_sec",
    "unique_src_ips", "unique_dst_ips", "tcp_count", "udp_count", "icmp_count",
]
FEATURE_COUNT = len(FEATURE_COLUMNS)


# ----------------------------
# Model Architecture & Setup
# ----------------------------
def build_model_architecture(input_shape):
    """Rebuild the model architecture to match training."""
    from tensorflow.keras import layers
    
    # Check if a model file exists to avoid unnecessary model rebuilding
    if MODEL_PATH.exists():
        return None # Return None if model is loaded from file

    print("Building model architecture (NO SAVED MODEL FOUND)...")
    inputs = layers.Input(shape=input_shape)
    attn = layers.MultiHeadAttention(
        num_heads=4, key_dim=input_shape[-1])(inputs, inputs)
    attn = layers.LayerNormalization(epsilon=1e-6)(inputs + attn)
    ffn = layers.Dense(64, activation="relu")(attn)
    ffn = layers.Dense(input_shape[-1])(ffn)
    x = layers.LayerNormalization(epsilon=1e-6)(attn + ffn)
    x = layers.GlobalAveragePooling1D()(x)
    outputs = layers.Dense(1, activation="sigmoid")(x)
    
    model = keras.Model(inputs, outputs)
    return model

def load_resources():
    """Loads the model and scaler."""
    # 1. Load Scaler
    if not SCALER_PATH.exists():
        print(f"Error: Scaler file not found at {SCALER_PATH}. Prediction cannot run.")
        sys.exit(1)
    scaler = joblib.load(SCALER_PATH)
    print(f"Loaded scaler from {SCALER_PATH}")

    # 2. Load Model
    if not MODEL_PATH.exists():
        # Fallback to building architecture if model file is missing
        model = build_model_architecture((SEQ_LEN, FEATURE_COUNT))
        if model is None:
             print(f"Error: Model file not found at {MODEL_PATH} and model could not be rebuilt.")
             sys.exit(1)
        # Note: A real model would require loaded weights. This is just a placeholder.
        print("WARNING: Using un-trained model architecture placeholder.")
    else:
        model = keras.models.load_model(MODEL_PATH)
        print(f"Loaded model from {MODEL_PATH}")

    return model, scaler


# ----------------------------
# Data Acquisition Workers (Fast C++ interaction)
# ----------------------------

def sniffing_worker(aggregator: 'FlowAggregator', stop_event: threading.Event):
    """
    Simulates a high-speed packet capture thread. 
    Passes raw packet data directly to the C++ aggregator.
    """
    # NOTE: In a real environment, this is where you would initialize Scapy 
    # and use sniff(prn=...) or similar high-performance tools.
    
    print("Sniffing worker started (MOCK).")
    
    # Mock data generation loop
    while not stop_event.is_set():
        # --- Mock Raw Packet Data ---
        # 1. Extract packet info:
        #    - flow_id: str (e.g., "192.168.1.1:12345:8.8.8.8:53:17")
        #    - packet_size: int 
        #    - protocol: int (6=TCP, 17=UDP, 1=ICMP)
        #    - current_time_ms: long long (Current timestamp in milliseconds)
        
        flow_id = "192.168.1.1:54321:1.1.1.1:53:17" # Dummy flow
        packet_size = np.random.randint(64, 1500)
        protocol = 17 # UDP
        current_time_ms = int(time.time() * 1000)
        
        # 2. Pass raw data to the C++ object
        # THIS CALL IS EXTREMELY FAST (O(1) lookup in C++ hash map)
        aggregator.update_flow(flow_id, packet_size, protocol, current_time_ms)
        
        # Adjust sleep based on expected packet rate. Very low sleep for high rate.
        time.sleep(0.0001) 

    print("Sniffing worker stopped.")

def pfsense_worker(aggregator: 'FlowAggregator', stop_event: threading.Event):
    """
    Simulates tailing a log file (like pfSense filter.log) and updating flow state.
    """
    print("pfSense worker started (MOCK).")
    
    # Mock data generation loop
    while not stop_event.is_set():
        # --- Mock Log Entry Data ---
        # In real life, you would parse a log line to get these values.
        flow_id = "10.0.0.10:80:192.168.1.100:43210:6" # Dummy flow
        packet_size = 64
        protocol = 6 # TCP
        current_time_ms = int(time.time() * 1000)
        
        # Pass raw data to the C++ object
        aggregator.update_flow(flow_id, packet_size, protocol, current_time_ms)
        
        time.sleep(0.01) # Log tailing is usually slower than sniffing

    print("pfSense worker stopped.")


# ----------------------------
# Prediction Worker (Slow Model interaction)
# ----------------------------

def predictor_worker(aggregator: 'FlowAggregator', model: keras.Model, scaler, stop_event: threading.Event):
    """
    Periodically checks the C++ aggregator for completed feature windows,
    scales, transforms the data into a sequence, and makes a prediction.
    """
    # Deque to hold the last SEQ_LEN feature windows
    history_buffer = deque(maxlen=SEQ_LEN)
    
    logf = open(LOG_FILE, 'a')
    print(f"Predictor worker started. Logging alerts to {LOG_FILE}")
    
    # Initialize the buffer with zeros to start (a common practice)
    dummy_window = np.zeros(FEATURE_COUNT)
    for _ in range(SEQ_LEN):
        history_buffer.append(dummy_window)

    while not stop_event.is_set():
        current_time_ms = int(time.time() * 1000)
        
        # 1. High-speed C++ check and flush
        # This returns a list of feature vectors (one for each flow in the completed window)
        feature_vectors = aggregator.check_and_flush_window(current_time_ms)
        
        if feature_vectors:
            # 2. Convert features to NumPy array
            # The C++ binding ensures this conversion is also fast.
            window_data = np.array(feature_vectors, dtype=np.float32)
            
            # --- Aggregation and Scaling (Must match training preprocessing) ---
            # In your training, the 10 features are computed *per flow*. 
            # If the model expects a single vector per window, you must aggregate 
            # the flows within this window (e.g., mean, max, or sum of features).
            
            # We will use the mean across all flows in the window as a simple representation
            window_feature_vector = np.mean(window_data, axis=0)
            
            # 3. Scale the window feature vector
            scaled_vector = scaler.transform(window_feature_vector.reshape(1, -1)).flatten()

            # 4. Update the sequence history
            history_buffer.append(scaled_vector)

            # 5. Prepare input for the Transformer (batch_size=1, SEQ_LEN, FEATURE_COUNT)
            # The buffer is already SEQ_LEN long.
            X_seq = np.array(history_buffer).reshape(1, SEQ_LEN, FEATURE_COUNT)

            # 6. Predict
            # Prediction is typically the slowest step.
            pred = model.predict(X_seq, verbose=0)[0][0]
            ts = time.strftime('%Y-%m-%d %H:%M:%S')

            # 7. Alerting Logic
            if pred >= PRED_THRESHOLD:
                # We can't determine the exact source of the attack from the aggregated window,
                # but we know the window itself is malicious.
                msg = f"{ts} ALERT: DDoS suspected (score={pred:.4f}). Window is anomalous."
                print(msg)
                logf.write(msg + "\n")
                logf.flush()
            else:
                # optional: print normal score occasionally
                print(f"{ts} OK score={pred:.4f}")
        
        # Allow other threads/tasks to run
        time.sleep(0.001)

    logf.close()
    print("Predictor worker stopped.")


# ----------------------------
# Main: start threads
# ----------------------------
def main():
    # The C++ object acts as the central shared data store, replacing the queue.
    # It must be initialized with the correct window size.
    try:
        aggregator = FlowAggregator(WINDOW_MS) 
    except Exception as e:
        print(f"Error initializing FlowAggregator (C++ binding issue?): {e}")
        return

    # Load model and scaler
    model, scaler = load_resources()
    
    stop_event = threading.Event()
    threads = []

    # Start data acquisition threads
    if ENABLE_SNIF:
        t_sniff = threading.Thread(target=sniffing_worker, args=(
            aggregator, stop_event), daemon=True)
        threads.append(t_sniff)
        t_sniff.start()

    if ENABLE_PFSENSE:
        t_pfs = threading.Thread(target=pfsense_worker, args=(
            aggregator, stop_event), daemon=True)
        threads.append(t_pfs)
        t_pfs.start()

    # Start the prediction thread
    t_pred = threading.Thread(target=predictor_worker, args=(
        aggregator, model, scaler, stop_event), daemon=True)
    threads.append(t_pred)
    t_pred.start()

    print("\n--- Detector Running ---")
    print(f"Window Size: {WINDOW_MS}ms, Sequence Length: {SEQ_LEN}")
    print("Press Ctrl+C to stop...\n")
    
    try:
        # Keep the main thread alive until a signal is received
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping detector...")
        stop_event.set()
    
    # Wait for threads to finish
    for t in threads:
        t.join(timeout=5)
    
    print("Detector stopped gracefully.")


if __name__ == "__main__":
    # Suppress TensorFlow warnings/messages
    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3' 
    # Must run main
    main()