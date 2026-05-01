#!/usr/bin/env python3
"""
ids_api.py — ML IDS REST API  (v5 — 16 features)
=================================================
Wraps best_model.pkl (XGBoost v5, retrained on MQTTset).

Features (16, must match model.metadata order):
  tcp.len, tcp.time_delta, tcp.flags,
  mqtt.msgtype, mqtt.msgid, mqtt.qos, mqtt.dupflag,
  mqtt.len, mqtt.kalive, mqtt.conack.val, mqtt.conflag.passwd,
  mqtt.retain,
  time_delta_mean, time_delta_std, pkt_rate, pub_to_conn_ratio

The last 4 are per-IP aggregate features computed by ids_api from a
sliding time window — NOT raw tshark fields.

Usage:
    python ids_api.py --model best_model.pkl \
                      --scaler scaler.pkl \
                      --encoder label_encoder.pkl \
                      --port 5000

Endpoints:
  POST /predict        — classify one packet's features
  POST /predict/batch  — classify a list of packets
  GET  /stats          — detection statistics
  GET  /health         — liveness check
  GET  /whitelist      — list whitelisted IPs
  POST /whitelist/add  — add IP to whitelist
  POST /whitelist/remove — remove IP from whitelist
  POST /reset          — clear per-IP state
"""

import argparse
import logging
import math
import os
import statistics
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

# ─── 16 features — MUST match model.metadata "features" order exactly ─────────
# 12 per-packet tshark features + 4 aggregate per-IP features.
FEATURE_NAMES = [
    "tcp.len",
    "tcp.time_delta",
    "tcp.flags",
    "mqtt.msgtype",
    "mqtt.msgid",
    "mqtt.qos",
    "mqtt.dupflag",
    "mqtt.len",
    "mqtt.kalive",
    "mqtt.conack.val",
    "mqtt.conflag.passwd",
    "mqtt.retain",
    # ── Per-IP aggregate features (computed here, not from tshark directly) ──
    "time_delta_mean",    # mean inter-packet interval in sliding window
    "time_delta_std",     # std  inter-packet interval in sliding window
    "pkt_rate",           # packets/sec in sliding window
    "pub_to_conn_ratio",  # PUBLISH count / CONNECT count in sliding window
]

# Tshark fields used for aggregate computation (not sent to model directly)
AGGREGATE_TSHARK_FIELDS = {"tcp.time_delta", "mqtt.msgtype"}

MODEL_ATTACK_LABELS   = {"bruteforce", "dos", "flood", "malformed", "slowite"}
REFINED_ATTACK_LABELS = {"flood", "malformed", "brute_force", "port_scan",
                         "slow_drip", "c2_malware", "dos"}
ATTACK_LABELS = MODEL_ATTACK_LABELS | REFINED_ATTACK_LABELS
BENIGN_LABEL  = "legitimate"

IP_WHITELIST = {
    "10.0.0.1", "10.0.0.2", "10.0.0.3",
    "10.0.0.4", "10.0.0.5", "10.0.0.6",
    "10.0.0.7", "10.0.0.8", "10.0.0.10",
    "127.0.0.1",
}

TRUSTED_SOURCES = {
    "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4",
    "10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8",
    "10.0.0.10",  # broker
}
NORMAL_MQTT_MSGTYPES  = {"1","2","3","4","5","6","7","8","9","10","11","12","13","14"}
ENABLE_TRUSTED_PREFILTER = os.environ.get("IDS_TRUSTED_PREFILTER", "1") == "1"
_trusted_prefilter_hits  = 0

BLOCK_CONFIDENCE_THRESHOLD = float(os.environ.get("IDS_BLOCK_CONF",  "0.90"))
BLOCK_VOTE_THRESHOLD       = int(  os.environ.get("IDS_BLOCK_VOTES", "20"))
VOTE_WINDOW_SIZE           = int(  os.environ.get("IDS_VOTE_WINDOW", "30"))

ip_vote_window: dict = defaultdict(lambda: deque(maxlen=VOTE_WINDOW_SIZE))

# ─── Per-IP sliding window for aggregate features ────────────────────────────
# Stores (timestamp, tcp.time_delta, mqtt.msgtype_int) per packet
AGG_WINDOW_SECS   = int(os.environ.get("IDS_AGG_WINDOW", "10"))  # seconds
AGG_MAX_HISTORY   = 500
ip_agg_window: dict = defaultdict(lambda: deque(maxlen=AGG_MAX_HISTORY))

# ─── Behavior-tracking window for subtype refinement ─────────────────────────
BEHAVIOR_WINDOW_SECS = 10.0
BEHAVIOR_MAX_HISTORY = 400
ip_behavior: dict = defaultdict(lambda: deque(maxlen=BEHAVIOR_MAX_HISTORY))

RYU_BLOCK_URL = os.environ.get("RYU_URL", "http://127.0.0.1:8080/ids/block")

stats           = defaultdict(int)
blocked_ips_log = []
start_time      = time.time()

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


# ─── Numeric conversion ───────────────────────────────────────────────────────

def to_num(val):
    """Convert any value to float. Supports hex strings, None, NaN, empty."""
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


# ─── Aggregate feature computation ───────────────────────────────────────────

def compute_aggregate_features(src_ip: str, raw: dict) -> dict:
    """
    Update the per-IP sliding window with the current packet and compute
    the 4 aggregate features required by model v5.

    Returns dict with keys: time_delta_mean, time_delta_std, pkt_rate,
                             pub_to_conn_ratio
    """
    now      = time.time()
    td       = to_num(raw.get("tcp.time_delta", 0))
    msgtype  = int(to_num(raw.get("mqtt.msgtype", 0)))

    # Append current packet to this IP's window
    ip_agg_window[src_ip].append((now, td, msgtype))

    # Prune entries older than AGG_WINDOW_SECS
    cutoff = now - AGG_WINDOW_SECS
    window = ip_agg_window[src_ip]
    while window and window[0][0] < cutoff:
        window.popleft()

    timestamps  = [e[0] for e in window]
    time_deltas = [e[1] for e in window]
    msgtypes    = [e[2] for e in window]

    n = len(time_deltas)

    # time_delta_mean / time_delta_std (from tcp.time_delta values in window)
    if n >= 2:
        td_mean = statistics.mean(time_deltas)
        td_std  = statistics.stdev(time_deltas) if n >= 3 else 0.0
    elif n == 1:
        td_mean = time_deltas[0]
        td_std  = 0.0
    else:
        td_mean = 0.0
        td_std  = 0.0

    # pkt_rate = packets in window / window duration (pkts/sec)
    if len(timestamps) >= 2:
        duration = timestamps[-1] - timestamps[0]
        pkt_rate = n / max(duration, 1e-6)
    else:
        pkt_rate = 0.0

    # pub_to_conn_ratio: PUBLISH(3) count / CONNECT(1) count
    pub_count  = msgtypes.count(3)
    conn_count = msgtypes.count(1)
    pub_to_conn_ratio = pub_count / max(conn_count, 1)

    return {
        "time_delta_mean":    td_mean,
        "time_delta_std":     td_std,
        "pkt_rate":           pkt_rate,
        "pub_to_conn_ratio":  pub_to_conn_ratio,
    }


# ─── Preprocessing ────────────────────────────────────────────────────────────

def preprocess_features(raw: dict, agg: dict) -> np.ndarray:
    """Convert tshark feature dict + aggregate dict → scaled numpy array."""
    combined = {**raw, **agg}
    row = [to_num(combined.get(col, 0)) for col in FEATURE_NAMES]
    X   = np.array([row], dtype=np.float32)
    Xs  = SCALER.transform(X)

    global _dbg_pre_logged
    if _dbg_pre_logged < DEBUG_LOG_FIRST_N:
        _dbg_pre_logged += 1
        LOG.info("[DBG-PRE #%d] raw  16feat = %s",
                 _dbg_pre_logged, dict(zip(FEATURE_NAMES, row)))
        LOG.info("[DBG-PRE #%d] scaled      = %s",
                 _dbg_pre_logged,
                 [round(float(v), 4) for v in Xs[0].tolist()])
        if all(v == 0.0 for v in row[:12]):
            LOG.warning("[DBG-PRE #%d]  ⚠ all-zero static features — pure TCP / no MQTT",
                        _dbg_pre_logged)
    return Xs


# ─── Behavior-based attack subtype refinement ─────────────────────────────────

def refine_attack_label(model_label: str, src_ip: str, raw: dict) -> str:
    """Return refined attack subtype based on src_ip's recent behavior.

    Rule priority (first match wins):
      1. slow_drip   — low pkt_rate + large PUBLISH payload
      2. flood       — SYN storm OR high-rate PUBLISH flood
      3. dos_flood   — high pkt_rate + CONNECT+PUBLISH mix (attack_dos.py pattern)
      4. malformed   — high CONNECT-only rate with no PUBLISH (raw TCP CONNECT spam)
                       OR out-of-spec msgtype ratio
      5. port_scan   — SYN + varying msgtypes
      6. brute_force — sustained CONNECT-only at moderate rate
      7. fallback    — model_label unchanged

    Signature notes per attack script:
      attack_malformed.py : sends raw TCP with MQTT-like bytes → tshark sees
                            msgtype=1 (CONNECT) only, pub_to_conn_ratio=0,
                            pkt_rate moderate (rate/10 connections × 10 pkts)
      attack_dos.py       : CONNECT + 50× PUBLISH per connection → pkt_rate
                            very high, pub_to_conn_ratio ≈ 1 (not >>1 like flood)
      attack1_flood.py    : pure PUBLISH storm → pub_to_conn_ratio >> 5
    """
    if model_label == BENIGN_LABEL or not src_ip:
        return model_label

    ts        = time.time()
    msgtype   = int(to_num(raw.get("mqtt.msgtype")))
    tcp_flags = int(to_num(raw.get("tcp.flags")))
    tcp_len   = int(to_num(raw.get("tcp.len")))
    mqtt_len  = int(to_num(raw.get("mqtt.len")))
    mqtt_msgid = to_num(raw.get("mqtt.msgid"))

    ip_behavior[src_ip].append((ts, msgtype, tcp_flags, tcp_len, mqtt_msgid, mqtt_len))

    # Prune stale entries
    cutoff = ts - BEHAVIOR_WINDOW_SECS
    buf    = ip_behavior[src_ip]
    while buf and buf[0][0] < cutoff:
        buf.popleft()

    recent = list(buf)
    if len(recent) < 3:
        return model_label

    msgtypes   = [e[1] for e in recent]
    flags_list = [e[2] for e in recent]
    tcp_lens   = [e[3] for e in recent]
    mqtt_lens  = [e[5] for e in recent]

    # ── Shared: compute pkt_rate from agg window ──────────────────────────────
    agg_buf  = ip_agg_window.get(src_ip)
    pkt_rate = 0.0
    if agg_buf and len(agg_buf) >= 2:
        ts_list  = [e[0] for e in agg_buf]
        duration = ts_list[-1] - ts_list[0]
        pkt_rate = len(agg_buf) / max(duration, 1e-6)

    pub_ratio    = msgtypes.count(3) / len(msgtypes)
    conn_ratio   = msgtypes.count(1) / len(msgtypes)
    avg_mqtt_len = sum(mqtt_lens) / len(mqtt_lens) if mqtt_lens else 0
    syn_ratio    = sum(1 for f in flags_list if (f & 0x02) and not (f & 0x10)) / len(flags_list)

    # ── Rule 1: Slow drip ─────────────────────────────────────────────────────
    # Low rate + mostly PUBLISH + large payload (base64 chunks)
    if pkt_rate < 2.0 and pub_ratio >= 0.5 and avg_mqtt_len > 50:
        return "slow_drip"

    # ── Rule 2: Pure PUBLISH flood (attack1_mqtt_flood.py) ───────────────────
    # Signature: very high pub_to_conn_ratio (>>3) + pub_ratio > 0.8
    agg_p2c = (agg_buf[-1] if agg_buf else None)  # get pub_to_conn from last agg
    # Recompute directly from behavior buffer for accuracy
    buf_pub  = msgtypes.count(3)
    buf_conn = msgtypes.count(1)
    buf_p2c  = buf_pub / max(buf_conn, 1)

    if pub_ratio > 0.8 and buf_p2c > 3.0 and pkt_rate > 20:
        return "flood"

    # ── Rule 3: SYN flood ────────────────────────────────────────────────────
    if syn_ratio > 0.7:
        return "flood"

    # ── Rule 4: DoS flood (attack_dos.py) ────────────────────────────────────
    # Signature: very high pkt_rate + pub_to_conn_ratio close to 1 (CONNECT
    # + fixed number of PUBLISH per connection) — distinguishable from flood
    # (p2c >> 3) and from brute_force (p2c ≈ 0).
    if pkt_rate > 30 and 0.3 <= buf_p2c <= 3.0:
        return "dos"

    # ── Rule 5: Malformed (attack_malformed.py) ───────────────────────────────
    # Signature: raw TCP CONNECT packets only → pub_to_conn_ratio = 0,
    # moderate pkt_rate (not the extreme of flood), small tcp.len.
    # Also catches out-of-spec msgtype bytes.
    malformed_ratio = sum(1 for m in msgtypes if m == 0 or m > 14) / len(msgtypes)
    avg_tcp_len = sum(tcp_lens) / len(tcp_lens) if tcp_lens else 0

    if malformed_ratio > 0.3 and pkt_rate >= 2.0:
        return "malformed"
    # Pure CONNECT spam with tiny packets = raw malformed CONNECT bytes
    if conn_ratio > 0.8 and buf_p2c == 0 and avg_tcp_len < 30 and pkt_rate > 2.0:
        return "malformed"

    # ── Rule 6: Port scan ─────────────────────────────────────────────────────
    if syn_ratio > 0.5 and len(set(msgtypes)) > 3:
        return "port_scan"

    # ── Rule 7: Brute force ───────────────────────────────────────────────────
    # Sustained CONNECT-only at moderate rate (not fast enough to be dos/flood,
    # not small-packet malformed)
    if conn_ratio > 0.5:
        return "brute_force"

    return model_label


# ─── Block via Ryu ────────────────────────────────────────────────────────────

def block_ip_via_ryu(src_ip: str, label: str):
    try:
        r = requests.post(RYU_BLOCK_URL, json={"ip": src_ip}, timeout=2.0)
        LOG.warning("Ryu block %s → %d %s", src_ip, r.status_code, r.text[:80])
        blocked_ips_log.append({
            "ip": src_ip, "label": label,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        LOG.error("Ryu block request failed for %s: %s", src_ip, e)


# ─── Core classification ──────────────────────────────────────────────────────

def classify(raw_features: dict, src_ip: str = None) -> dict:
    """Classify one packet. Returns prediction result dict."""
    global _trusted_prefilter_hits

    # Trusted-source pre-filter (skip ML for known-good hosts)
    if ENABLE_TRUSTED_PREFILTER and src_ip in TRUSTED_SOURCES:
        msgtype = str(int(to_num(raw_features.get("mqtt.msgtype", 0))))
        if msgtype in NORMAL_MQTT_MSGTYPES:
            _trusted_prefilter_hits += 1
            if _trusted_prefilter_hits <= DEBUG_LOG_FIRST_N:
                LOG.info("[DBG-TRUST] hit #%d src=%s msgtype=%s -> legitimate",
                         _trusted_prefilter_hits, src_ip, msgtype)
            # Still update aggregate window so state stays consistent
            compute_aggregate_features(src_ip, raw_features)
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

    # Compute aggregate features for this src_ip
    agg = compute_aggregate_features(src_ip or "__unknown__", raw_features)

    X     = preprocess_features(raw_features, agg)
    proba = MODEL.predict_proba(X)[0]
    idx   = int(np.argmax(proba))
    model_label = LABEL_ENCODER.inverse_transform([idx])[0]
    conf  = float(proba[idx])

    global _dbg_cls_logged, _dbg_pred_counter
    _dbg_pred_counter[model_label] += 1
    if _dbg_cls_logged < DEBUG_LOG_FIRST_N:
        _dbg_cls_logged += 1
        proba_d = {LABEL_ENCODER.inverse_transform([i])[0]: round(float(p), 3)
                   for i, p in enumerate(proba)}
        LOG.info("[DBG-CLS #%d] src=%-15s model_label=%-12s conf=%.3f probas=%s",
                 _dbg_cls_logged, src_ip or "-", model_label, conf, proba_d)
    if sum(_dbg_pred_counter.values()) % 200 == 0:
        LOG.info("[DBG-DIST] cumulative model_label histogram: %s",
                 dict(_dbg_pred_counter.most_common()))

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
        "agg_features": {k: round(v, 4) for k, v in agg.items()},
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
        "model":    "XGBoost v5 (MQTTset, 16 features)",
        "features": FEATURE_NAMES,
        "classes":  list(LABEL_ENCODER.classes_) if LABEL_ENCODER else [],
        "uptime_s": round(time.time() - start_time, 1),
        "agg_window_secs": AGG_WINDOW_SECS,
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
        "trusted_prefilter_hits": _trusted_prefilter_hits,
        "config": {
            "features":             FEATURE_NAMES,
            "n_features":           len(FEATURE_NAMES),
            "whitelist":            sorted(IP_WHITELIST),
            "confidence_threshold": BLOCK_CONFIDENCE_THRESHOLD,
            "block_vote_threshold": BLOCK_VOTE_THRESHOLD,
            "vote_window_size":     VOTE_WINDOW_SIZE,
            "agg_window_secs":      AGG_WINDOW_SECS,
        },
        "ip_vote_windows": {
            ip: {"recent_attacks": sum(w), "window_size": len(w)}
            for ip, w in ip_vote_window.items()
        },
        "ip_agg_windows": {
            ip: {"buffered_pkts": len(buf)}
            for ip, buf in ip_agg_window.items()
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


@app.route("/reset", methods=["POST"])
def reset_state():
    """Clear per-IP vote / behavior / aggregate windows.
    Body: {"ip": "10.0.0.99"} to scope to one IP, omit to clear all.
          {"stats": true}      to also zero the stats counters."""
    body = request.get_json(silent=True) or {}
    ip   = (body.get("ip") or "").strip()
    if ip:
        ip_vote_window.pop(ip, None)
        ip_behavior.pop(ip, None)
        ip_agg_window.pop(ip, None)
        LOG.info("Reset state for %s", ip)
        scope = ip
    else:
        ip_vote_window.clear()
        ip_behavior.clear()
        ip_agg_window.clear()
        LOG.info("Reset state for ALL ips")
        scope = "all"
    if body.get("stats"):
        stats.clear()
    return jsonify({"status": "reset", "scope": scope})


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MQTT IDS API v5 — 16 features")
    parser.add_argument("--model",   default="best_model.pkl")
    parser.add_argument("--scaler",  default="scaler.pkl")
    parser.add_argument("--encoder", default="label_encoder.pkl")
    parser.add_argument("--port",    type=int, default=5000)
    parser.add_argument("--host",    default="0.0.0.0")
    args = parser.parse_args()

    load_models(args.model, args.scaler, args.encoder)

    LOG.info("IDS API v5 starting on %s:%d", args.host, args.port)
    LOG.info("Ryu block endpoint : %s", RYU_BLOCK_URL)
    LOG.info("Aggregate window   : %ds", AGG_WINDOW_SECS)
    app.run(host=args.host, port=args.port, debug=False, threaded=True)
