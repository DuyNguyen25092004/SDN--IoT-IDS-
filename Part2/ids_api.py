#!/usr/bin/env python3
"""
ids_api.py — ML IDS REST API
==============================
Wraps best_model_xgb.pkl (XGBoost, trained on MQTTset).
Receives the exact 33 features tshark extracts, returns
classification label + confidence, and auto-blocks malicious IPs
via the Ryu Flow Enforcer REST endpoint.

Usage:
    python ids_api.py --model /path/to/best_model_xgb.pkl \
                      --scaler /path/to/scaler.pkl \
                      --encoder /path/to/label_encoder.pkl \
                      --feat-encoder /path/to/feature_encoders.pkl \
                      --port 5000

Endpoints:
  POST /predict        — classify one packet's features
  POST /predict/batch  — classify a list of packets
  GET  /stats          — detection statistics
  GET  /health         — liveness check
"""

import argparse
import json
import logging
import os
import time
from collections import defaultdict
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
import requests
from collections import Counter
from flask import Flask, jsonify, request

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [IDS-API] %(levelname)s %(message)s"
)
LOG = logging.getLogger("ids_api")

app = Flask(__name__)

# ─── Global model objects (loaded at startup) ─────────────────────────────────
MODEL           = None
SCALER          = None
LABEL_ENCODER   = None
FEATURE_ENCODERS = None   # dict of {col: LabelEncoder} for categorical features

# ─── The exact 33 features from MQTTset / best_model_xgb.pkl ─────────────────
FEATURE_NAMES = [
    "tcp.flags",
    "tcp.time_delta",
    "tcp.len",
    "mqtt.conack.flags",
    "mqtt.conack.flags.reserved",
    "mqtt.conack.flags.sp",
    "mqtt.conack.val",
    "mqtt.conflag.cleansess",
    "mqtt.conflag.passwd",
    "mqtt.conflag.qos",
    "mqtt.conflag.reserved",
    "mqtt.conflag.retain",
    "mqtt.conflag.uname",
    "mqtt.conflag.willflag",
    "mqtt.conflags",
    "mqtt.dupflag",
    "mqtt.hdrflags",
    "mqtt.kalive",
    "mqtt.len",
    "mqtt.msg",
    "mqtt.msgid",
    "mqtt.msgtype",
    "mqtt.proto_len",
    "mqtt.protoname",
    "mqtt.qos",
    "mqtt.retain",
    "mqtt.sub.qos",
    "mqtt.suback.qos",
    "mqtt.ver",
    "mqtt.willmsg",
    "mqtt.willmsg_len",
    "mqtt.willtopic",
    "mqtt.willtopic_len",
]

# Labels the model outputs (from model_metadata.json)
ATTACK_LABELS = {"bruteforce", "dos", "flood", "malformed", "slowite"}
BENIGN_LABEL  = "legitimate"

# ─── Protection: never auto-block these IPs ───────────────────────────────────
# Includes broker and all legitimate publisher/subscriber IPs
IP_WHITELIST = {
    "10.0.0.1",  "10.0.0.2",  "10.0.0.3",
    "10.0.0.4",  "10.0.0.5",  "10.0.0.6",
    "10.0.0.7",  "10.0.0.8",  "10.0.0.10",
    "127.0.0.1",
}

# Minimum confidence to even consider a block (0.0 = disabled)
BLOCK_CONFIDENCE_THRESHOLD = 0.90

# Number of attack detections within VOTE_WINDOW_SIZE packets before blocking
BLOCK_VOTE_THRESHOLD = 20    # need 5 attack detections...
VOTE_WINDOW_SIZE     = 30   # ...within a sliding window of 10 packets per IP

# Per-IP sliding window: ip → deque of recent labels
from collections import deque
ip_vote_window: dict = defaultdict(lambda: deque(maxlen=VOTE_WINDOW_SIZE))

# ─── Ryu controller endpoint ─────────────────────────────────────────────────
RYU_BLOCK_URL = os.environ.get("RYU_URL", "http://127.0.0.1:8080/ids/block")

# ─── Statistics ───────────────────────────────────────────────────────────────
stats = defaultdict(int)   # label → count
blocked_ips_log = []       # list of {ip, label, time}
start_time = time.time()


# ─── Model loading ────────────────────────────────────────────────────────────

def load_models(model_path, scaler_path, encoder_path, feat_enc_path):
    global MODEL, SCALER, LABEL_ENCODER, FEATURE_ENCODERS

    LOG.info("Loading model from %s", model_path)
    MODEL = joblib.load(model_path)

    LOG.info("Loading scaler from %s", scaler_path)
    SCALER = joblib.load(scaler_path)

    LOG.info("Loading label encoder from %s", encoder_path)
    LABEL_ENCODER = joblib.load(encoder_path)

    if feat_enc_path and os.path.exists(feat_enc_path):
        LOG.info("Loading feature encoders from %s", feat_enc_path)
        FEATURE_ENCODERS = joblib.load(feat_enc_path)
    else:
        LOG.warning("No feature encoders path provided — skipping")
        FEATURE_ENCODERS = {}

    LOG.info("Models loaded. Classes: %s", list(LABEL_ENCODER.classes_))


# ─── Preprocessing (mirrors the notebook's preprocess() function) ─────────────

def preprocess_features(raw: dict) -> np.ndarray:
    """
    Convert raw tshark field dict → model-ready numpy array.
    Matches the preprocessing in mqttset_ids_notebook_before_run.ipynb.
    """
    row = {}
    for col in FEATURE_NAMES:
        val = raw.get(col, 0)
        # tshark exports empty string for missing fields
        if val == "" or val is None:
            val = 0
        # Hex strings (e.g. tcp.flags = "0x002") → int
        if isinstance(val, str):
            val = val.strip()
            if val.startswith("0x") or val.startswith("0X"):
                try:
                    val = int(val, 16)
                except ValueError:
                    val = 0
            else:
                try:
                    val = float(val)
                except ValueError:
                    # categorical — encode
                    if col in FEATURE_ENCODERS:
                        try:
                            val = FEATURE_ENCODERS[col].transform([val])[0]
                        except Exception:
                            val = 0
                    else:
                        val = 0
        row[col] = val

    df = pd.DataFrame([row], columns=FEATURE_NAMES)

    # Apply feature encoders for any remaining object columns
    for col in df.select_dtypes(include=["object"]).columns:
        if col in FEATURE_ENCODERS:
            try:
                df[col] = FEATURE_ENCODERS[col].transform(df[col].astype(str))
            except Exception:
                df[col] = 0
        else:
            df[col] = 0

    df = df.fillna(0)
    X = SCALER.transform(df.values)
    return X


# ─── Ryu integration ─────────────────────────────────────────────────────────

def block_ip_via_ryu(src_ip: str, label: str):
    """Send block command to Ryu Flow Enforcer."""
    try:
        resp = requests.post(
            RYU_BLOCK_URL,
            json={"ip": src_ip},
            timeout=2
        )
        LOG.warning("ATTACK DETECTED [%s] src=%s → Ryu block: %s",
                    label, src_ip, resp.json())
        blocked_ips_log.append({
            "ip": src_ip,
            "label": label,
            "time": datetime.now().isoformat()
        })
    except requests.exceptions.ConnectionError:
        LOG.error("Cannot reach Ryu controller at %s — is it running?",
                  RYU_BLOCK_URL)
    except Exception as e:
        LOG.error("Ryu block failed: %s", e)


# ─── Prediction logic ─────────────────────────────────────────────────────────

def classify(raw_features: dict, src_ip: str = None) -> dict:
    """
    Classify one packet's feature dict.
    Returns: {label, confidence, is_attack, src_ip, blocked}

    Blocking only happens when ALL of:
      1. is_attack == True
      2. confidence >= BLOCK_CONFIDENCE_THRESHOLD
      3. src_ip is NOT in IP_WHITELIST
      4. The sliding window for this IP has >= BLOCK_VOTE_THRESHOLD attacks
    """
    X = preprocess_features(raw_features)

    proba  = MODEL.predict_proba(X)[0]
    idx    = int(np.argmax(proba))
    label  = LABEL_ENCODER.inverse_transform([idx])[0]
    conf   = float(proba[idx])

    is_attack = label in ATTACK_LABELS
    stats[label] += 1

    # Update sliding vote window for this IP
    blocked = False
    if src_ip:
        ip_vote_window[src_ip].append(1 if is_attack else 0)
        attack_votes = sum(ip_vote_window[src_ip])
    else:
        attack_votes = 0

    result = {
        "label":        label,
        "confidence":   round(conf, 4),
        "is_attack":    is_attack,
        "attack_votes": attack_votes,
        "src_ip":       src_ip or "unknown",
        "timestamp":    datetime.now().isoformat(),
        "blocked":      False,
    }

    if is_attack and src_ip:
        LOG.warning("ATTACK [%s] conf=%.2f votes=%d/%d src=%s",
                    label, conf, attack_votes, VOTE_WINDOW_SIZE, src_ip)

        # Gate: whitelist check
        if src_ip in IP_WHITELIST:
            LOG.info("  → Skipping block: %s is whitelisted", src_ip)
        # Gate: confidence threshold
        elif conf < BLOCK_CONFIDENCE_THRESHOLD:
            LOG.info("  → Skipping block: conf %.2f < threshold %.2f",
                     conf, BLOCK_CONFIDENCE_THRESHOLD)
        # Gate: vote window
        elif attack_votes < BLOCK_VOTE_THRESHOLD:
            LOG.info("  → Skipping block: only %d/%d votes accumulated",
                     attack_votes, BLOCK_VOTE_THRESHOLD)
        else:
            LOG.warning("  → BLOCKING src=%s (all gates passed)", src_ip)
            block_ip_via_ryu(src_ip, label)
            result["blocked"] = True
    else:
        LOG.debug("OK    [%s] conf=%.2f src=%s", label, conf, src_ip)

    return result


# ─── Flask endpoints ──────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "model":  "XGBoost (MQTTset)",
        "uptime_s": round(time.time() - start_time, 1)
    })


@app.route("/predict", methods=["POST"])
def predict():
    """
    Body: {
      "src_ip": "10.0.0.99",          # optional — triggers Ryu block if attack
      "features": { ...33 fields... }
    }
    """
    if MODEL is None:
        return jsonify({"error": "Model not loaded"}), 503

    body = request.get_json(silent=True)
    if not body or "features" not in body:
        return jsonify({"error": "Missing 'features' key"}), 400

    result = classify(body["features"], src_ip=body.get("src_ip"))
    return jsonify(result)


@app.route("/predict/batch", methods=["POST"])
def predict_batch():
    """
    Body: [
      {"src_ip": "...", "features": {...}},
      ...
    ]
    """
    if MODEL is None:
        return jsonify({"error": "Model not loaded"}), 503

    items = request.get_json(silent=True)
    if not isinstance(items, list):
        return jsonify({"error": "Expected a JSON array"}), 400

    results = []
    for item in items:
        try:
            r = classify(item.get("features", {}), src_ip=item.get("src_ip"))
            results.append(r)
        except Exception as e:
            results.append({"error": str(e)})

    return jsonify(results)


@app.route("/stats", methods=["GET"])
def get_stats():
    total = sum(stats.values())
    return jsonify({
        "total_packets":    total,
        "by_label":         dict(stats),
        "blocked_events":   blocked_ips_log[-50:],
        "uptime_s":         round(time.time() - start_time, 1),
        "config": {
            "whitelist":             sorted(IP_WHITELIST),
            "confidence_threshold":  BLOCK_CONFIDENCE_THRESHOLD,
            "block_vote_threshold":  BLOCK_VOTE_THRESHOLD,
            "vote_window_size":      VOTE_WINDOW_SIZE,
        },
        "ip_vote_windows": {
            ip: {"recent_attacks": sum(w), "window_size": len(w)}
            for ip, w in ip_vote_window.items()
        },
    })


@app.route("/whitelist", methods=["GET"])
def get_whitelist():
    return jsonify({"whitelist": sorted(IP_WHITELIST)})


@app.route("/whitelist/add", methods=["POST"])
def add_whitelist():
    body = request.get_json(silent=True)
    ip = (body or {}).get("ip", "").strip()
    if not ip:
        return jsonify({"error": "missing ip"}), 400
    IP_WHITELIST.add(ip)
    LOG.info("Added %s to whitelist", ip)
    return jsonify({"status": "added", "ip": ip, "whitelist": sorted(IP_WHITELIST)})


@app.route("/whitelist/remove", methods=["POST"])
def remove_whitelist():
    body = request.get_json(silent=True)
    ip = (body or {}).get("ip", "").strip()
    if not ip:
        return jsonify({"error": "missing ip"}), 400
    IP_WHITELIST.discard(ip)
    LOG.info("Removed %s from whitelist", ip)
    return jsonify({"status": "removed", "ip": ip, "whitelist": sorted(IP_WHITELIST)})


# ─── Entry point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MQTT IDS API")
    parser.add_argument("--model",        default="best_model_xgb.pkl")
    parser.add_argument("--scaler",       default="scaler.pkl")
    parser.add_argument("--encoder",      default="label_encoder.pkl")
    parser.add_argument("--feat-encoder", default="feature_encoders.pkl")
    parser.add_argument("--port",         type=int, default=5000)
    parser.add_argument("--host",         default="0.0.0.0")
    args = parser.parse_args()

    load_models(args.model, args.scaler, args.encoder, args.feat_encoder)

    LOG.info("IDS API starting on %s:%d", args.host, args.port)
    LOG.info("Ryu block endpoint: %s", RYU_BLOCK_URL)
    app.run(host=args.host, port=args.port, debug=False, threaded=True)