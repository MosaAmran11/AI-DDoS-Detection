#!/usr/bin/env python3
"""
Common feature engineering helpers shared by the training
and real-time inference scripts.

The helpers are derived directly from the structure of the
KDD Cup 1999 dataset. They standardize column names, handle
categorical features, and build a feature vector for DDoS detection.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, Tuple, List

import numpy as np  # type: ignore
import pandas as pd  # type: ignore
from sklearn.ensemble import RandomForestClassifier  # type: ignore
from sklearn.preprocessing import LabelEncoder  # type: ignore

# KDD Cup 1999 dataset column names (41 features + 1 label + 1 difficulty)
KDD_COLUMNS = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty'
]

# Categorical columns that need encoding
CATEGORICAL_COLUMNS = ['protocol_type', 'service', 'flag']

# Ordered list of top features (will be set after feature selection)
FEATURE_COLUMNS: List[str] = []


def load_kdd_dataset(dataset_dir: Path) -> pd.DataFrame:
    """
    Load KDD Cup 1999 dataset from .txt files.
    Returns a DataFrame with proper column names.
    """
    txt_files = sorted(dataset_dir.glob("*.txt"))
    if not txt_files:
        raise FileNotFoundError(f"No .txt files found in {dataset_dir}")

    frames = []
    for txt_path in txt_files:
        print(f"Loading {txt_path.name}...")
        df = pd.read_csv(txt_path, header=None, low_memory=False)
        frames.append(df)

    raw_df = pd.concat(frames, ignore_index=True)
    raw_df.columns = KDD_COLUMNS
    return raw_df


def clean_kdd_dataframe(df: pd.DataFrame) -> Tuple[pd.DataFrame, np.ndarray]:
    """
    Clean and preprocess KDD dataset.
    Handles categorical encoding and label conversion.
    Returns (features_dataframe, labels_array)
    """
    cleaned = df.copy()

    # Convert label to binary: normal=0, attack=1
    cleaned['label'] = cleaned['label'].astype(str).str.strip()
    cleaned['is_attack'] = (cleaned['label'] != 'normal').astype(int)
    labels = cleaned['is_attack'].to_numpy(dtype=int)

    # Encode categorical features
    label_encoders = {}
    for col in CATEGORICAL_COLUMNS:
        if col in cleaned.columns:
            le = LabelEncoder()
            cleaned[col] = le.fit_transform(cleaned[col].astype(str))
            label_encoders[col] = le

    # Select all feature columns (exclude label and difficulty - difficulty is metadata, not a feature)
    feature_cols = [col for col in KDD_COLUMNS if col not in [
        'label', 'difficulty']]
    features_df = cleaned[feature_cols].copy()

    # Convert to numeric, handling any non-numeric values
    for col in features_df.columns:
        features_df[col] = pd.to_numeric(features_df[col], errors='coerce')

    # Replace problematic values
    features_df = features_df.replace([np.inf, -np.inf], np.nan)
    features_df = features_df.fillna(0)

    # Remove duplicates
    features_df = features_df.drop_duplicates()
    # Keep labels aligned
    labels = labels[features_df.index]
    features_df = features_df.reset_index(drop=True)

    return features_df, labels


def select_top_features(features_df: pd.DataFrame, labels: np.ndarray, n_features: int = 10) -> List[str]:
    """
    Use Random Forest to select top N most important features for DDoS detection.
    Returns list of feature names.
    """
    print(f"\nSelecting top {n_features} features using Random Forest...")

    # Train Random Forest for feature importance
    rf = RandomForestClassifier(
        n_estimators=100, random_state=42, n_jobs=-1, max_depth=20)
    rf.fit(features_df, labels)

    # Get feature importances
    feature_importance = pd.DataFrame({
        'feature': features_df.columns,
        'importance': rf.feature_importances_
    }).sort_values('importance', ascending=False)

    print("\nTop 10 most important features:")
    print(feature_importance.head(n_features).to_string(index=False))

    top_features = feature_importance.head(n_features)['feature'].tolist()
    return top_features


def build_feature_dataframe(df: pd.DataFrame, selected_features: List[str] = None) -> Tuple[pd.DataFrame, np.ndarray]:
    """
    Convert the cleaned KDD dataframe into feature space for the Transformer.
    If selected_features is None, will use all features.
    Returns (features_dataframe, labels_array)
    """
    features_df, labels = clean_kdd_dataframe(df)

    if selected_features:
        # Use only selected features
        available_features = [
            f for f in selected_features if f in features_df.columns]
        if len(available_features) != len(selected_features):
            missing = set(selected_features) - set(available_features)
            print(
                f"Warning: Missing features {missing}, using available ones.")
        features_df = features_df[available_features]

    return features_df.astype(float), labels


def save_feature_metadata(path: Path, features: List[str]) -> None:
    """Persist the ordered feature list for downstream scripts."""
    path.write_text(
        pd.Series(features).to_json(orient="values"),
        encoding="utf-8",
    )


def load_feature_metadata(path: Path) -> List[str]:
    """Load the persisted feature order if it exists."""
    if not path.exists():
        return []
    data = pd.read_json(path, typ="series")
    ordered = data.tolist()
    return ordered if ordered else []
