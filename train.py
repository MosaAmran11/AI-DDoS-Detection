#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path
from typing import Tuple

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import tensorflow as tf
from tensorflow.keras import layers
import joblib

from feature_config import (
    FEATURE_COLUMNS,
    build_feature_dataframe,
    save_feature_metadata,
)


def resolve_paths() -> Tuple[Path, Path]:
    dataset_dir = Path(os.environ.get("DATASET_DIR", ROOT / "dataset"))
    artifact_dir = Path(os.environ.get("ARTIFACT_DIR", ROOT))

    artifact_dir.mkdir(parents=True, exist_ok=True)
    if not dataset_dir.exists():
        raise FileNotFoundError(
            f"Dataset directory '{dataset_dir}' not found. "
            "Set DATASET_DIR to the folder that contains CSV files."
        )
    return dataset_dir, artifact_dir


def load_dataset(dataset_dir: Path) -> Tuple[pd.DataFrame, np.ndarray]:
    csv_files = sorted(dataset_dir.glob("*.csv"))
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {dataset_dir}")

    frames = []
    for csv_path in csv_files:
        print(f"Loading {csv_path} ...")
        frames.append(pd.read_csv(csv_path))

    raw_df = pd.concat(frames, ignore_index=True)
    features, labels = build_feature_dataframe(raw_df)
    print(f"Dataset shape after cleaning: {features.shape}")
    return features, labels


def to_sequences(data: np.ndarray, labels: np.ndarray, window: int) -> Tuple[np.ndarray, np.ndarray]:
    seq_data = []
    seq_labels = []
    for i in range(len(data) - window):
        seq_data.append(data[i : i + window])
        seq_labels.append(labels[i + window])
    return np.array(seq_data), np.array(seq_labels)


def build_model(input_shape: Tuple[int, int]) -> tf.keras.Model:
    inputs = layers.Input(shape=input_shape)
    attn = layers.MultiHeadAttention(num_heads=4, key_dim=input_shape[-1])(inputs, inputs)
    attn = layers.LayerNormalization(epsilon=1e-6)(inputs + attn)
    ffn = layers.Dense(64, activation="relu")(attn)
    ffn = layers.Dense(input_shape[-1])(ffn)
    x = layers.LayerNormalization(epsilon=1e-6)(attn + ffn)
    x = layers.GlobalAveragePooling1D()(x)
    x = layers.Dense(64, activation="relu")(x)
    outputs = layers.Dense(1, activation="sigmoid")(x)
    model = tf.keras.Model(inputs=inputs, outputs=outputs)
    model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])
    return model


def main():
    mount_drive_if_needed()
    dataset_dir, artifact_dir = resolve_paths()

    model_path = artifact_dir / "model" / "ddos_transformer.h5"
    scaler_path = artifact_dir / "model" / "scaler.gz"
    feature_meta_path = artifact_dir / "model" / "feature_columns.json"

    features, labels = load_dataset(dataset_dir)

    scaler = StandardScaler()
    scaled = scaler.fit_transform(features.values)
    X_seq, y_seq = to_sequences(scaled, labels, WINDOW)

    X_train, X_test, y_train, y_test = train_test_split(
        X_seq, y_seq, test_size=0.2, random_state=42, stratify=y_seq
    )

    model = build_model((WINDOW, len(FEATURE_COLUMNS)))
    model.summary()

    model.fit(
        X_train,
        y_train,
        validation_data=(X_test, y_test),
        epochs=10,
        batch_size=128,
    )

    model.save(model_path)
    joblib.dump(scaler, scaler_path)
    save_feature_metadata(feature_meta_path)
    print(f"Artifacts saved to:\n  {model_path}\n  {scaler_path}\n  {feature_meta_path}")


if __name__ == "__main__":
    main()
