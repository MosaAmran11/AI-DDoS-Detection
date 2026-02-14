#!/usr/bin/env python3
"""
Common feature engineering helpers shared by the training
and real-time inference scripts.

The helpers are derived directly from the structure of the
CSV dataset shipped in ``dataset/sample.csv``. They standardize
column names, drop unused textual columns, and build a compact
feature vector that mirrors what the live detector can compute.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, Tuple

import numpy as np  # type: ignore
import pandas as pd  # type: ignore

# Ordered list of numeric features used for both training
# and inference. Keep this synchronized with the real-time
# feature extractor to avoid shape mismatches.
FEATURE_COLUMNS = [
    "packet_count",
    "byte_count",
    "avg_pkt_size",
    "std_pkt_size",
    "duration_sec",
    "unique_src_ips",
    "unique_dst_ips",
    "tcp_count",
    "udp_count",
    "icmp_count",
]

# Columns in the raw dataset that are either identifiers,
# textual labels, or otherwise not helpful for the model.
DROP_COLUMNS = {
    "flow_id",
    "source_ip",
    "source_port",
    "destination_ip",
    "destination_port",
    "timestamp",
    "simillarhttp",
    "inbound",
}


def _normalize_column_name(name: str) -> str:
    return (
        name.strip()
        .replace(" ", "_")
        .replace("/", "_")
        .replace(".", "_")
        .replace("-", "_")
        .lower()
    )


def clean_raw_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Standardize column names, drop unused columns, and sanitize values."""
    cleaned = df.copy()
    cleaned.columns = [_normalize_column_name(c) for c in cleaned.columns]
    cleaned = cleaned.loc[:, ~cleaned.columns.duplicated()]

    unnamed_cols = [c for c in cleaned.columns if c.startswith("unnamed")]
    cleaned = cleaned.drop(columns=unnamed_cols + list(DROP_COLUMNS), errors="ignore")

    # Ensure label column exists and is binary.
    if "label" not in cleaned.columns:
        raise ValueError("Dataset does not contain a 'Label' column.")

    cleaned["label"] = (
        cleaned["label"]
        .astype(str)
        .str.strip()
        .str.upper()
        .map(lambda v: 0 if v == "BENIGN" else 1)
        .astype(int)
    )

    # Replace problematic numeric values.
    cleaned = cleaned.replace([np.inf, -np.inf], np.nan)
    cleaned = cleaned.dropna()
    cleaned = cleaned.drop_duplicates()
    return cleaned


def _numeric_series(df: pd.DataFrame, column: str, default: float = 0.0) -> pd.Series:
    if column not in df.columns:
        return pd.Series(default, index=df.index, dtype=float)
    return pd.to_numeric(df[column], errors="coerce").fillna(default)


def build_feature_dataframe(df: pd.DataFrame) -> Tuple[pd.DataFrame, np.ndarray]:
    """
    Convert the cleaned CIC-style dataframe into the compact
    numeric feature space expected by the Transformer.
    Returns (features_dataframe, labels_array)
    """
    cleaned = clean_raw_dataframe(df)

    total_fwd_packets = _numeric_series(cleaned, "total_fwd_packets")
    total_bwd_packets = _numeric_series(cleaned, "total_backward_packets")
    total_fwd_len = _numeric_series(cleaned, "total_length_of_fwd_packets")
    total_bwd_len = _numeric_series(cleaned, "total_length_of_bwd_packets")
    pkt_len_mean = _numeric_series(cleaned, "packet_length_mean")
    pkt_len_std = _numeric_series(cleaned, "packet_length_std")
    flow_duration = _numeric_series(cleaned, "flow_duration").clip(lower=1.0)
    protocol = _numeric_series(cleaned, "protocol").astype(int)

    feature_frame = pd.DataFrame(
        {
            "packet_count": total_fwd_packets + total_bwd_packets,
            "byte_count": total_fwd_len + total_bwd_len,
            "avg_pkt_size": pkt_len_mean,
            "std_pkt_size": pkt_len_std,
            "duration_sec": flow_duration / 1_000_000.0,  # microseconds -> seconds
            "unique_src_ips": 1.0,  # single flow per row
            "unique_dst_ips": 1.0,
            "tcp_count": (protocol == 6).astype(float),
            "udp_count": (protocol == 17).astype(float),
            "icmp_count": (protocol == 1).astype(float),
        },
        index=cleaned.index,
    )

    labels = cleaned["label"].to_numpy(dtype=int)
    return feature_frame.astype(float), labels


def save_feature_metadata(path: Path) -> None:
    """Persist the ordered feature list for downstream scripts."""
    path.write_text(
        pd.Series(FEATURE_COLUMNS).to_json(orient="values"),
        encoding="utf-8",
    )


def load_feature_metadata(path: Path) -> Iterable[str]:
    """Load the persisted feature order if it exists."""
    if not path.exists():
        return FEATURE_COLUMNS
    data = pd.read_json(path, typ="series")
    ordered = data.tolist()
    if not ordered:
        return FEATURE_COLUMNS
    return ordered

