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
from collections import defaultdict, deque, Counter
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

# ─── 8 features — MUST match the training order in model_metadata_v2.json ────
# The scaler/model are positional: any reorder corrupts every prediction.
# (Importance ranking is for analysis only — do NOT use it as feature order.)
FEATURE_NAMES = [
    "mqtt.qos",
    "mqtt.hdrflags",
    "tcp.len",
    "mqtt.msgtype",
    "mqtt.retain",
    "tcp.flags",
    "mqtt.msgid",
    "tcp.time_delta",
]

# Raw model classes from MQTTset training
MODEL_ATTACK_LABELS = {"bruteforce", "dos", "flood", "malformed", "slowite"}
# Refined subtype labels emitted by the behavior layer (see refine_attack_label)
REFINED_ATTACK_LABELS = {"flood", "malformed", "brute_force", "port_scan", "slow_drip", "c2_malware", "dos"}
ATTACK_LABELS = MODEL_ATTACK_LABELS | REFINED_ATTACK_LABELS
BENIGN_LABEL  = "legitimate"

IP_WHITELIST = {
    "10.0.0.1", "10.0.0.2", "10.0.0.3",
    "10.0.0.4", "10.0.0.5", "10.0.0.6",
    "10.0.0.7", "10.0.0.8", "10.0.0.10",
    "127.0.0.1",
}

# ─── Trusted-source pre-filter ────────────────────────────────────────────────
# Sensor hosts h1-h8 and the broker only ever produce well-formed MQTT
# control packets. The 6-class MQTTset model has overlapping per-packet
# labels (the same {qos,hdr,len,msgtype,...} vector appears under both
# "legitimate" and "dos"), so the raw model collapses normal traffic
# into "dos". When the source IP is known-trusted AND the packet carries
# a standard MQTT message type, short-circuit to `legitimate` without
# invoking the model. Attackers (10.0.0.99) bypass this and hit the model.
TRUSTED_SOURCES = {
    "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4",
    "10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8",
    "10.0.0.10",  # broker
}
# Standard MQTT 3.1.1 control packet types (as seen in mqtt.msgtype):
# 1=CONNECT 2=CONNACK 3=PUBLISH 4=PUBACK 5=PUBREC 6=PUBREL 7=PUBCOMP
# 8=SUBSCRIBE 9=SUBACK 10=UNSUBSCRIBE 11=UNSUBACK 12=PINGREQ 13=PINGRESP 14=DISCONNECT
NORMAL_MQTT_MSGTYPES = {"1","2","3","4","5","6","7","8","9","10","11","12","13","14"}
ENABLE_TRUSTED_PREFILTER = os.environ.get("IDS_TRUSTED_PREFILTER", "1") == "1"
_trusted_prefilter_hits = 0

BLOCK_CONFIDENCE_THRESHOLD = float(os.environ.get("IDS_BLOCK_CONF",  "0.90"))
BLOCK_VOTE_THRESHOLD       = int(  os.environ.get("IDS_BLOCK_VOTES", "20"))
VOTE_WINDOW_SIZE           = int(  os.environ.get("IDS_VOTE_WINDOW", "30"))

ip_vote_window: dict = defaultdict(lambda: deque(maxlen=VOTE_WINDOW_SIZE))

# ─── Behavior-tracking window for subtype refinement ─────────────────────────
# Each entry: (ts, mqtt_msgtype, tcp_flags, tcp_len, mqtt_msgid)
BEHAVIOR_WINDOW_SECS = 10.0
BEHAVIOR_MAX_HISTORY = 400
ip_behavior: dict = defaultdict(lambda: deque(maxlen=BEHAVIOR_MAX_HISTORY))

RYU_BLOCK_URL = os.environ.get("RYU_URL", "http://127.0.0.1:8080/ids/block")

stats           = defaultdict(int)
blocked_ips_log = []
start_time      = time.time()

# ─── DEBUG instrumentation ───────────────────────────────────────────────────
# Set DEBUG_LOG_FIRST_N>0 to dump full per-prediction detail (raw vector,
# scaled vector, full proba dict) for the first N predictions. Toggle with
# the IDS_DEBUG_N env var (default 20).
DEBUG_LOG_FIRST_N = int(os.environ.get("IDS_DEBUG_N", "20"))
_dbg_pre_logged   = 0
_dbg_cls_logged   = 0
_dbg_pred_counter = Counter()


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
    Xs  = SCALER.transform(X)

    # ---- DEBUG: log first N raw+scaled vectors so we can SEE what the
    # model actually receives. Toggle via DEBUG_LOG_FIRST_N global.
    global _dbg_pre_logged
    if _dbg_pre_logged < DEBUG_LOG_FIRST_N:
        _dbg_pre_logged += 1
        LOG.info("[DBG-PRE #%d] raw   8feat = %s",
                 _dbg_pre_logged, dict(zip(FEATURE_NAMES, row)))
        LOG.info("[DBG-PRE #%d] scaled       = %s",
                 _dbg_pre_logged,
                 [round(float(v), 4) for v in Xs[0].tolist()])
        if all(v == 0.0 for v in row):
            LOG.warning("[DBG-PRE #%d]   ⚠ all-zero raw vector — pure TCP / no MQTT layer",
                        _dbg_pre_logged)
    return Xs


# ─── Behavior-based attack subtype refinement ────────────────────────────────
# The MQTTset 6-class model reliably says "is_attack=True" but cannot
# distinguish port_scan / c2_malware / brute_force / slow_drip — it has no
# class for the first two and feature set is per-packet only.
# We track per-IP packet patterns and override the subtype label.
#
# MQTT message types: 1=CONNECT 2=CONNACK 3=PUBLISH 8=SUBSCRIBE 12=PINGREQ
# TCP flag bits     : 0x02=SYN 0x10=ACK 0x18=PUSH+ACK 0x04=RST
def refine_attack_label(model_label: str, src_ip: str, raw: dict) -> str:
    """Return refined attack subtype based on src_ip's recent behavior.
    Rules are evaluated in order; first match wins. Falls back to model_label
    when no rule has high enough evidence.

    NOTE: This layer is reliable for FLOOD and (when traffic is captured on
    all ports) PORT_SCAN. Distinguishing brute_force / slow_drip / c2_malware
    is brittle when attacks are short-lived (early blocks) or when the
    capture filter excludes non-MQTT ports. Retraining with explicit classes
    + aggregate features remains the proper fix.
    """
    if model_label == BENIGN_LABEL or not src_ip:
        return model_label

    ts        = time.time()
    msgtype   = int(to_num(raw.get("mqtt.msgtype")))
    tcp_flags = int(to_num(raw.get("tcp.flags")))
    tcp_len   = int(to_num(raw.get("tcp.len")))
    msgid     = int(to_num(raw.get("mqtt.msgid")))

    hist = ip_behavior[src_ip]
    hist.append((ts, msgtype, tcp_flags, tcp_len, msgid))

    cutoff = ts - BEHAVIOR_WINDOW_SECS
    recent = [h for h in hist if h[0] >= cutoff]
    n      = len(recent)
    if n < 5:
        return model_label

    span_s     = max(0.001, recent[-1][0] - recent[0][0])
    rate       = n / span_s
    n_syn_only = sum(1 for _, mt, fl, ln, _ in recent
                     if mt == 0 and (fl & 0x02) and ln == 0)
    n_connect  = sum(1 for _, mt, *_ in recent if mt == 1)
    n_publish  = sum(1 for _, mt, *_ in recent if mt == 3)
    n_mqtt     = sum(1 for _, mt, *_ in recent if mt > 0)
    pub_ts     = [t for t, mt, *_ in recent if mt == 3]

    # 1) flood — sustained high packet rate dominated by PUBLISH
    if rate >= 30.0 and n_publish >= 20:
        return "flood"

    # 2) port_scan — pure SYN bursts, NO MQTT activity at all
    #    (only fires when capture is NOT filtered to port 1883)
    if n_syn_only >= 5 and n_mqtt == 0:
        return "port_scan"

    # 3) brute_force — rapid CONNECTs with NO successful publishes
    if n_connect >= 5 and n_publish == 0:
        return "brute_force"

    # 4) slow_drip — sustained low-rate PUBLISHes over a meaningful span
    if 0.4 <= rate <= 5.0 and n_publish >= 3 and span_s >= 4.0:
        return "slow_drip"

    # 5) c2_malware — model labelled it malformed, moderate periodic PUBLISHes
    if (model_label == "malformed" and 1.0 <= rate <= 15.0
            and n_publish >= 3 and len(pub_ts) >= 3):
        deltas = [pub_ts[i] - pub_ts[i - 1] for i in range(1, len(pub_ts))]
        if deltas:
            lo = max(0.001, min(deltas))
            hi = max(deltas)
            if hi / lo < 5.0 and lo >= 0.05:
                return "c2_malware"

    # No rule matched — keep the model's verdict (likely flood/malformed)
    return model_label


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
    # ---- Trusted-source pre-filter (rule layer before the ML model) -------
    # If the packet comes from a known sensor host or the broker AND it
    # carries a standard MQTT control type, label it `legitimate` directly.
    # This eliminates the per-packet ambiguity in the MQTTset training set
    # (where the same vector appears under both legitimate and dos).
    global _trusted_prefilter_hits
    if ENABLE_TRUSTED_PREFILTER and src_ip in TRUSTED_SOURCES:
        msgtype = str(raw_features.get("mqtt.msgtype", "")).strip()
        if msgtype in NORMAL_MQTT_MSGTYPES:
            _trusted_prefilter_hits += 1
            if _trusted_prefilter_hits <= 5 or _trusted_prefilter_hits % 500 == 0:
                LOG.info("[DBG-TRUST] hit #%d src=%s msgtype=%s -> legitimate",
                         _trusted_prefilter_hits, src_ip, msgtype)
            stats[BENIGN_LABEL] += 1
            return {
                "label":        BENIGN_LABEL,
                "model_label":  BENIGN_LABEL,
                "confidence":   1.0,
                "is_attack":    False,
                "attack_votes": 0,
                "src_ip":       src_ip,
                "timestamp":    datetime.now().isoformat(),
                "blocked":      False,
                "trusted_prefilter": True,
            }

    X     = preprocess_features(raw_features)
    proba = MODEL.predict_proba(X)[0]
    idx   = int(np.argmax(proba))
    model_label = LABEL_ENCODER.inverse_transform([idx])[0]
    conf  = float(proba[idx])

    # ---- DEBUG: full per-class probability distribution for first N preds.
    global _dbg_cls_logged, _dbg_pred_counter
    _dbg_pred_counter[model_label] += 1
    if _dbg_cls_logged < DEBUG_LOG_FIRST_N:
        _dbg_cls_logged += 1
        proba_d = {LABEL_ENCODER.inverse_transform([i])[0]: round(float(p), 3)
                   for i, p in enumerate(proba)}
        LOG.info("[DBG-CLS #%d] src=%-15s model_label=%-12s conf=%.3f probas=%s",
                 _dbg_cls_logged, src_ip or "-", model_label, conf, proba_d)
    # Periodic prediction histogram (every 200 classifications)
    if sum(_dbg_pred_counter.values()) % 200 == 0:
        LOG.info("[DBG-DIST] cumulative model_label histogram: %s",
                 dict(_dbg_pred_counter.most_common()))

    # Anomaly decision comes from the ML model; subtype refined by behavior.
    is_attack = model_label in MODEL_ATTACK_LABELS
    label     = refine_attack_label(model_label, src_ip, raw_features) if is_attack else model_label
    stats[label] += 1

    if src_ip:
        ip_vote_window[src_ip].append(1 if is_attack else 0)
        attack_votes = sum(ip_vote_window[src_ip])
    else:
        attack_votes = 0

    result = {
        "label":        label,
        "model_label":  model_label,
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
