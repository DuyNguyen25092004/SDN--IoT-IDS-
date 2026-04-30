#!/usr/bin/env python3
"""
ids_api.py — ML IDS REST API  (v2 — 8 features)
=================================================
Wraps best_model_xgb_v2.pkl (XGBoost, retrained on MQTTset).

Features (8, ranked by importance):
  mqtt.msgid, tcp.len, mqtt.msgtype, mqtt.hdrflags,
  mqtt.qos, tcp.flags, tcp.time_delta, mqtt.retain

Usage:
    python ids_api.py --model best_model_xgb_v2.pkl \
                      --scaler scaler_v2.pkl \
                      --encoder label_encoder_v2.pkl \
                      --port 5000

Endpoints:
  POST /predict        — classify one packet's features
  POST /predict/batch  — classify a list of packets
  GET  /stats          — detection statistics
  GET  /health         — liveness check
  GET  /whitelist      — list whitelisted IPs
  POST /whitelist/add  — add IP to whitelist
  POST /whitelist/remove — remove IP from whitelist
"""

import argparse
import logging
import os
import time
from collections import defaultdict, deque
from datetime import datetime

import joblib
import numpy as np
import requests
from flask import Flask, jsonify, request

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [IDS-API] %(levelname)s %(message)s"
)
LOG = logging.getLogger("ids_api")

app = Flask(__name__)

# ─── Global model objects ─────────────────────────────────────────────────────
MODEL         = None
SCALER        = None
LABEL_ENCODER = None

# ─── 8 features — theo thứ tự importance thực tế từ model ────────────────────
# mqtt.msgid      0.3219  ← dominant: bruteforce có msgid tuần tự/lặp
# tcp.len         0.1375  ← payload size (DoS/flood = 0)
# mqtt.msgtype    0.1358  ← loại MQTT packet
# mqtt.hdrflags   0.1220  ← MQTT header flags (PUBLISH=0x30, CONNECT=0x10...)
# mqtt.qos        0.1038  ← Quality of Service bất thường trong attack
# tcp.flags       0.0900  ← SYN/RST/ACK → phân biệt DoS SYN flood
# tcp.time_delta  0.0575  ← inter-packet time cực nhỏ = flood/DoS
# mqtt.retain     0.0315  ← retain flag bất thường trong attack
FEATURE_NAMES = [
    "mqtt.msgid",
    "tcp.len",
    "mqtt.msgtype",
    "mqtt.hdrflags",
    "mqtt.qos",
    "tcp.flags",
    "tcp.time_delta",
    "mqtt.retain",
]

ATTACK_LABELS = {"bruteforce", "dos", "flood", "malformed", "slowite"}
BENIGN_LABEL  = "legitimate"

IP_WHITELIST = {
    "10.0.0.1", "10.0.0.2", "10.0.0.3",
    "10.0.0.4", "10.0.0.5", "10.0.0.6",
    "10.0.0.7", "10.0.0.8", "10.0.0.10",
    "127.0.0.1",
}

BLOCK_CONFIDENCE_THRESHOLD = 0.90
BLOCK_VOTE_THRESHOLD       = 20
VOTE_WINDOW_SIZE           = 30

ip_vote_window: dict = defaultdict(lambda: deque(maxlen=VOTE_WINDOW_SIZE))
RYU_BLOCK_URL = os.environ.get("RYU_URL", "http://127.0.0.1:8080/ids/block")

stats           = defaultdict(int)
blocked_ips_log = []
start_time      = time.time()


# ─── Model loading ────────────────────────────────────────────────────────────

def load_models(model_path, scaler_path, encoder_path):
    global MODEL, SCALER, LABEL_ENCODER
    LOG.info("Loading model   : %s", model_path)
    MODEL = joblib.load(model_path)
    LOG.info("Loading scaler  : %s", scaler_path)
    SCALER = joblib.load(scaler_path)
    LOG.info("Loading encoder : %s", encoder_path)
    LABEL_ENCODER = joblib.load(encoder_path)
    LOG.info("Classes  : %s", list(LABEL_ENCODER.classes_))
    LOG.info("Features (%d): %s", len(FEATURE_NAMES), FEATURE_NAMES)


# ─── Preprocessing ────────────────────────────────────────────────────────────

def to_num(val):
    """
    Chuyển bất kỳ giá trị nào thành float.
    Hỗ trợ: hex string "0x00000018", float, int, None, empty.
    """
    if val is None or (isinstance(val, float) and val != val):
        return 0.0
    s = str(val).strip()
    if not s or s in ("nan", "None", ""):
        return 0.0
    if s.startswith(("0x", "0X")):
        try:
            return float(int(s, 16))
        except ValueError:
            return 0.0
    try:
        return float(s)
    except ValueError:
        return 0.0


def preprocess_features(raw: dict) -> np.ndarray:
    """Convert tshark feature dict → model-ready numpy array (scaled)."""
    row = [to_num(raw.get(col, 0)) for col in FEATURE_NAMES]
    X   = np.array([row], dtype=np.float32)
    return SCALER.transform(X)


# ─── Ryu integration ─────────────────────────────────────────────────────────

def block_ip_via_ryu(src_ip: str, label: str):
    try:
        resp = requests.post(RYU_BLOCK_URL, json={"ip": src_ip}, timeout=2)
        LOG.warning("BLOCKED src=%s label=%s ryu=%s", src_ip, label, resp.json())
        blocked_ips_log.append({
            "ip": src_ip, "label": label,
            "time": datetime.now().isoformat(),
        })
    except requests.exceptions.ConnectionError:
        LOG.error("Cannot reach Ryu controller at %s", RYU_BLOCK_URL)
    except Exception as e:
        LOG.error("Ryu block failed: %s", e)


# ─── Prediction logic ─────────────────────────────────────────────────────────

def classify(raw_features: dict, src_ip: str = None) -> dict:
    X     = preprocess_features(raw_features)
    proba = MODEL.predict_proba(X)[0]
    idx   = int(np.argmax(proba))
    label = LABEL_ENCODER.inverse_transform([idx])[0]
    conf  = float(proba[idx])

    is_attack = label in ATTACK_LABELS
    stats[label] += 1

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
        if src_ip in IP_WHITELIST:
            LOG.info("  -> Skip block: %s whitelisted", src_ip)
        elif conf < BLOCK_CONFIDENCE_THRESHOLD:
            LOG.info("  -> Skip block: conf %.2f < %.2f threshold",
                     conf, BLOCK_CONFIDENCE_THRESHOLD)
        elif attack_votes < BLOCK_VOTE_THRESHOLD:
            LOG.info("  -> Skip block: %d/%d votes (need %d)",
                     attack_votes, VOTE_WINDOW_SIZE, BLOCK_VOTE_THRESHOLD)
        else:
            LOG.warning("  -> BLOCKING src=%s", src_ip)
            block_ip_via_ryu(src_ip, label)
            result["blocked"] = True
    else:
        LOG.debug("OK [%s] conf=%.2f src=%s", label, conf, src_ip)

    return result


# ─── Flask endpoints ──────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status":   "ok",
        "model":    "XGBoost v2 (MQTTset, 8 features)",
        "features": FEATURE_NAMES,
        "classes":  list(LABEL_ENCODER.classes_) if LABEL_ENCODER else [],
        "uptime_s": round(time.time() - start_time, 1),
    })


@app.route("/predict", methods=["POST"])
def predict():
    if MODEL is None:
        return jsonify({"error": "Model not loaded"}), 503
    body = request.get_json(silent=True)
    if not body or "features" not in body:
        return jsonify({"error": "Missing 'features' key"}), 400
    try:
        result = classify(body["features"], src_ip=body.get("src_ip"))
    except Exception as e:
        LOG.error("Predict error: %s", e)
        return jsonify({"error": str(e)}), 500
    return jsonify(result)


@app.route("/predict/batch", methods=["POST"])
def predict_batch():
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
        "total_packets":  total,
        "by_label":       dict(stats),
        "blocked_events": blocked_ips_log[-50:],
        "uptime_s":       round(time.time() - start_time, 1),
        "config": {
            "features":             FEATURE_NAMES,
            "whitelist":            sorted(IP_WHITELIST),
            "confidence_threshold": BLOCK_CONFIDENCE_THRESHOLD,
            "block_vote_threshold": BLOCK_VOTE_THRESHOLD,
            "vote_window_size":     VOTE_WINDOW_SIZE,
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
    ip   = (body or {}).get("ip", "").strip()
    if not ip:
        return jsonify({"error": "missing 'ip'"}), 400
    IP_WHITELIST.add(ip)
    LOG.info("Whitelist add: %s", ip)
    return jsonify({"status": "added", "ip": ip, "whitelist": sorted(IP_WHITELIST)})


@app.route("/whitelist/remove", methods=["POST"])
def remove_whitelist():
    body = request.get_json(silent=True)
    ip   = (body or {}).get("ip", "").strip()
    if not ip:
        return jsonify({"error": "missing 'ip'"}), 400
    IP_WHITELIST.discard(ip)
    LOG.info("Whitelist remove: %s", ip)
    return jsonify({"status": "removed", "ip": ip, "whitelist": sorted(IP_WHITELIST)})


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MQTT IDS API v2 — 8 features")
    parser.add_argument("--model",   default="best_model_xgb_v2.pkl")
    parser.add_argument("--scaler",  default="scaler_v2.pkl")
    parser.add_argument("--encoder", default="label_encoder_v2.pkl")
    parser.add_argument("--port",    type=int, default=5000)
    parser.add_argument("--host",    default="0.0.0.0")
    args = parser.parse_args()

    load_models(args.model, args.scaler, args.encoder)

    LOG.info("IDS API v2 starting on %s:%d", args.host, args.port)
    LOG.info("Ryu block endpoint : %s", RYU_BLOCK_URL)
    app.run(host=args.host, port=args.port, debug=False, threaded=True)
