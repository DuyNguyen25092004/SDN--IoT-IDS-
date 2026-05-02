#!/usr/bin/env python3
"""
verify_vector_format.py (V2)
=======================
Diagnoses WHY the SDN IoT IDS detects incorrectly by comparing:
  1. The feature vector the MODEL was trained on (from dataset CSV + scaler.pkl)
  2. The feature vector the RUNTIME sends to the model (from tshark / ids_api.py)
"""

import argparse
import json
import sys
import os
import numpy as np
import pandas as pd

# ──────────────────────────────────────────────────────────────
#  The 8 features hardcoded in ids_api.py (runtime side - v2)
# ──────────────────────────────────────────────────────────────
RUNTIME_FEATURE_NAMES = [
    "mqtt.qos",
    "mqtt.hdrflags",
    "tcp.len",
    "mqtt.msgtype",
    "mqtt.retain",
    "tcp.flags",
    "mqtt.msgid",
    "tcp.time_delta"
]

# ──────────────────────────────────────────────────────────────
#  Simulated runtime packets
# ──────────────────────────────────────────────────────────────
SAMPLE_NORMAL_PACKET = {
    "tcp.flags":                   "0x0018",  # PSH+ACK
    "tcp.time_delta":              "0.001234",
    "tcp.len":                     "45",
    "mqtt.hdrflags":               "0x30",
    "mqtt.msgtype":                "3",   # PUBLISH
    "mqtt.qos":                    "0",
    "mqtt.retain":                 "0",
    "mqtt.msgid":                  "",
}

SAMPLE_FLOOD_PACKET = {
    **SAMPLE_NORMAL_PACKET,
    "tcp.time_delta": "0.000001",   # very fast — flood
    "tcp.len":        "45",
    "mqtt.msgtype":   "3",
}

SAMPLE_BRUTEFORCE_PACKET = {
    **SAMPLE_NORMAL_PACKET,
    "mqtt.msgtype":        "1",   # CONNECT
    "mqtt.hdrflags":       "0x10",
    "tcp.time_delta":      "0.000050",
    "mqtt.msgid":          "1234", # Bruteforce often has rapid sequential msg IDs
}

# ══════════════════════════════════════════════════════════════
#  SECTION 1 — Dataset-side analysis
# ══════════════════════════════════════════════════════════════

def analyse_dataset(csv_path: str) -> dict:
    print("\n" + "═" * 65)
    print("  SECTION 1 — DATASET FEATURE VECTOR")
    print("═" * 65)
    print(f"  Loading: {csv_path}")

    df = pd.read_csv(csv_path, nrows=5000)
    all_cols = list(df.columns)

    label_candidates = ["label", "target", "class", "attack", "type"]
    label_col = None
    for col in all_cols:
        if col.lower() in label_candidates:
            label_col = col
            break
    if label_col is None:
        label_col = all_cols[-1]

    feature_cols = [c for c in all_cols if c != label_col]

    print(f"\n  Total columns in CSV : {len(all_cols)}")
    print(f"  Label column         : '{label_col}'")
    print(f"  Feature columns      : {len(feature_cols)}")
    
    # Check if dataset has 8 features or if it's the raw 33
    if len(feature_cols) > len(RUNTIME_FEATURE_NAMES):
        print(f"  Note: Dataset has {len(feature_cols)} features. We will only analyze the {len(RUNTIME_FEATURE_NAMES)} V2 features.")
        feature_cols = [c for c in feature_cols if c in RUNTIME_FEATURE_NAMES]

    print(f"\n  ANALYZED DATASET COLUMNS:")
    for i, col in enumerate(feature_cols):
        print(f"    {i+1:3d}. {col}")

    return {
        "all_columns":   all_cols,
        "feature_cols":  feature_cols,
        "label_col":     label_col,
        "n_features":    len(feature_cols),
        "label_values":  sorted(df[label_col].unique().tolist()),
        "dtypes":        {str(k): int(v) for k, v in df[feature_cols].dtypes.value_counts().items()},
    }

# ══════════════════════════════════════════════════════════════
#  SECTION 2 — Runtime vector analysis
# ══════════════════════════════════════════════════════════════

def analyse_runtime() -> dict:
    print("\n" + "═" * 65)
    print("  SECTION 2 — RUNTIME FEATURE VECTOR (ids_api.py - V2)")
    print("═" * 65)
    print(f"\n  Hardcoded feature count : {len(RUNTIME_FEATURE_NAMES)}")
    print(f"\n  ALL RUNTIME FEATURES (from ids_api.FEATURE_NAMES):")
    for i, col in enumerate(RUNTIME_FEATURE_NAMES):
        print(f"    {i+1:3d}. {col}")

    return {
        "feature_names": RUNTIME_FEATURE_NAMES,
        "n_features":    len(RUNTIME_FEATURE_NAMES),
    }

# ══════════════════════════════════════════════════════════════
#  SECTION 3 — Cross-comparison: dataset vs runtime
# ══════════════════════════════════════════════════════════════

def compare_vectors(dataset_info: dict, runtime_info: dict):
    print("\n" + "═" * 65)
    print("  SECTION 3 — MISMATCH ANALYSIS")
    print("═" * 65)

    ds_features  = set(dataset_info["feature_cols"])
    rt_features  = set(runtime_info["feature_names"])
    ds_list      = dataset_info["feature_cols"]
    rt_list      = runtime_info["feature_names"]

    in_ds_not_rt = ds_features - rt_features
    in_rt_not_ds = rt_features - ds_features
    common       = ds_features & rt_features

    print(f"\n  Missing from RUNTIME : {len(in_ds_not_rt)} features")
    for col in sorted(in_ds_not_rt):
        print(f"    ✗  '{col}'")

    print(f"\n  Missing from DATASET : {len(in_rt_not_ds)} features")
    for col in sorted(in_rt_not_ds):
        print(f"    ✗  '{col}'")

    print(f"\n  Common features      : {len(common)}")

    print(f"\n  ORDER CHECK:")
    order_ok = True
    # For V2, we care about the exact order the Scaler expects. 
    # Usually this is the order of RUNTIME_FEATURE_NAMES
    for i, col in enumerate(rt_list):
        if col in ds_list:
            print(f"    [{i:2d}] ✅  '{col}' is present")
        else:
            print(f"    [{i:2d}] ❌  '{col}' is missing")
            order_ok = False

    return {
        "count_match":        len(ds_features) == len(rt_features),
        "missing_in_runtime": sorted(in_ds_not_rt),
        "extra_in_runtime":   sorted(in_rt_not_ds),
        "common_count":       len(common),
    }

# ══════════════════════════════════════════════════════════════
#  SECTION 4 — Scaler / pkl analysis
# ══════════════════════════════════════════════════════════════

def analyse_scaler(scaler_path: str, metadata_path: str, dataset_info: dict):
    print("\n" + "═" * 65)
    print("  SECTION 4 — SCALER & MODEL METADATA")
    print("═" * 65)

    try:
        import joblib
        scaler = joblib.load(scaler_path)
        n_scaler_features = scaler.n_features_in_
        print(f"\n  scaler.pkl n_features_in_  : {n_scaler_features}")

        if n_scaler_features != len(RUNTIME_FEATURE_NAMES):
            print(f"  ⚠  SCALER vs RUNTIME: scaler has {n_scaler_features} features,")
            print(f"     but runtime sends {len(RUNTIME_FEATURE_NAMES)} features")
        else:
            print(f"  ✅ Scaler feature count matches runtime: {n_scaler_features}")

        if hasattr(scaler, "feature_names_in_"):
            scaler_cols = list(scaler.feature_names_in_)
            print(f"\n  SCALER COLUMN NAMES (what it was fitted on):")
            for i, col in enumerate(scaler_cols):
                rt_match = col in RUNTIME_FEATURE_NAMES
                status = "✅" if rt_match else "❌ NOT in runtime"
                print(f"    {i+1:3d}. {col:<20} {status}")
                
            if scaler_cols == RUNTIME_FEATURE_NAMES:
                print("\n  ✅ Scaler order matches Runtime order perfectly!")
            else:
                print("\n  ❌ SCALER ORDER MISMATCH: The order of features in the scaler does NOT match RUNTIME_FEATURE_NAMES.")

    except Exception as e:
        print(f"\n  ⚠  Could not load scaler: {e}")

    if metadata_path and os.path.exists(metadata_path):
        with open(metadata_path) as f:
            meta = json.load(f)
        print(f"\n  MODEL METADATA ({metadata_path}):")
        print(f"    n_features   : {meta.get('n_features')}")
        trained_feats = meta.get("feature_names", [])
        if trained_feats:
            if trained_feats == RUNTIME_FEATURE_NAMES:
                print(f"  ✅ Training features == Runtime features (perfect match)")
            else:
                print(f"  ❌ Mismatch between training features and runtime.")
                print(f"     Trained: {trained_feats}")
                print(f"     Runtime: {RUNTIME_FEATURE_NAMES}")

# ══════════════════════════════════════════════════════════════
#  SECTION 5 — Runtime preprocess simulation
# ══════════════════════════════════════════════════════════════

def simulate_runtime_preprocess():
    print("\n" + "═" * 65)
    print("  SECTION 5 — SIMULATE RUNTIME PREPROCESSING (ids_api.py - V2)")
    print("═" * 65)

    def preprocess_like_ids_api(raw: dict) -> dict:
        """Mirrors ids_api.py to_num() logic exactly."""
        row = {}
        for col in RUNTIME_FEATURE_NAMES:
            val = raw.get(col, 0)
            if val is None or (isinstance(val, float) and val != val):
                final_val = 0.0
            else:
                s = str(val).strip()
                if not s or s in ("nan", "None", ""):
                    final_val = 0.0
                elif s.startswith(("0x", "0X")):
                    try:
                        final_val = float(int(s, 16))
                    except ValueError:
                        final_val = 0.0
                else:
                    try:
                        final_val = float(s)
                    except ValueError:
                        final_val = 0.0
            row[col] = final_val
        return row

    samples = {
        "NORMAL PUBLISH":     SAMPLE_NORMAL_PACKET,
        "FLOOD ATTACK":       SAMPLE_FLOOD_PACKET,
        "BRUTE FORCE CONNECT":SAMPLE_BRUTEFORCE_PACKET,
    }

    for name, raw in samples.items():
        processed = preprocess_like_ids_api(raw)
        values    = list(processed.values())
        nonzero   = sum(1 for v in values if v != 0)
        zero      = len(values) - nonzero

        print(f"\n  [{name}]")
        print(f"    Non-zero features : {nonzero}/{len(values)}")
        print(f"    Feature values:")
        for feat, val in processed.items():
            nonzero_marker = "" if val == 0 else " ←"
            print(f"      {feat:<20} = {val}{nonzero_marker}")

# ══════════════════════════════════════════════════════════════
#  Entry point
# ══════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv",      default="",                help="Path to MQTTset CSV")
    parser.add_argument("--scaler",   default="scaler_v2.pkl",   help="Path to scaler_v2.pkl")
    parser.add_argument("--encoder",  default="label_encoder_v2.pkl")
    parser.add_argument("--metadata", default="model_metadata_v2.json")
    args = parser.parse_args()

    print("\n" + "╔" + "═"*63 + "╗")
    print("║   SDN IoT IDS — V2 Feature Vector Verification Tool       ║")
    print("╚" + "═"*63 + "╝")

    runtime_info = analyse_runtime()

    if args.csv and os.path.exists(args.csv):
        dataset_info = analyse_dataset(args.csv)
        compare_vectors(dataset_info, runtime_info)
        analyse_scaler(args.scaler, args.metadata, dataset_info)

    simulate_runtime_preprocess()

if __name__ == "__main__":
    main()