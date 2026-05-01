#!/usr/bin/env python3
"""
test_ids.py — Script test nhanh IDS pipeline
=============================================
Chạy TRƯỚC khi bật Mininet để xác nhận model hoạt động đúng.

Usage:
    python3 test_ids.py --api http://127.0.0.1:5000
    python3 test_ids.py --api http://127.0.0.1:5000 --verbose
"""

import argparse
import json
import sys

import requests

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"


def ok(msg):  print(f"  {GREEN}✓{RESET} {msg}")
def fail(msg): print(f"  {RED}✗{RESET} {msg}")
def warn(msg): print(f"  {YELLOW}⚠{RESET} {msg}")
def info(msg): print(f"  {CYAN}→{RESET} {msg}")


def test_health(api: str):
    print(f"\n{BOLD}[1] Health check{RESET}")
    r = requests.get(f"{api}/health", timeout=5)
    d = r.json()
    ok(f"API lên, version={d.get('version')}, uptime={d.get('uptime_s')}s")
    ok(f"Classes: {d.get('classes')}")
    ok(f"Features: {d.get('features')}")


def test_zero_bias(api: str):
    print(f"\n{BOLD}[2] Test model bias với all-zero vector{RESET}")
    r = requests.get(f"{api}/debug/zero_test", timeout=5)
    d = r.json()
    label = d.get("prediction")
    info(f"All-zero → '{label}' (conf={d.get('confidence')})")
    info(f"All proba: {d.get('all_proba')}")
    if label == "malformed":
        ok("Xác nhận: model default ra 'malformed' khi features = 0")
        warn("Đây là root cause của bug — tshark trả empty → 0 → malformed")
    else:
        ok(f"Unexpected: model ra '{label}' với all-zero (có thể model version khác)")


def test_feature_parse(api: str, verbose: bool):
    print(f"\n{BOLD}[3] Test debug/features — kiểm tra to_num() parse{RESET}")

    # Case 1: tshark-style hex string
    features_hex = {
        "mqtt.qos": "0", "mqtt.hdrflags": "0x30",
        "tcp.len": "256", "mqtt.msgtype": "3",
        "mqtt.retain": "0", "tcp.flags": "0x0018",
        "mqtt.msgid": "0", "tcp.time_delta": "0.0001",
    }
    r = requests.post(f"{api}/debug/features", json={"features": features_hex}, timeout=5)
    d = r.json()
    if verbose:
        for f in d["features"]:
            print(f"    {f['feature']:20s} raw={f['raw_input']:10s} → {f['parsed']}")
    if d["quality_ok"]:
        ok(f"Hex string parse OK (zero_count={d['zero_count']}/8)")
    else:
        fail(f"Parse warning: {d['warning']}")

    # Case 2: tshark empty fields (bug lũ cũ)
    features_empty = {col: "" for col in [
        "mqtt.qos", "mqtt.hdrflags", "tcp.len", "mqtt.msgtype",
        "mqtt.retain", "tcp.flags", "mqtt.msgid", "tcp.time_delta"
    ]}
    r2 = requests.post(f"{api}/debug/features", json={"features": features_empty}, timeout=5)
    d2 = r2.json()
    if not d2["quality_ok"]:
        ok(f"API phát hiện được lỗi tshark empty fields ({d2['zero_count']}/8 = 0)")
    else:
        fail("API không phát hiện được lỗi tshark empty fields")


def test_attack_classify(api: str, verbose: bool):
    TESTS = [
        {
            "name":     "MQTT Flood (Attack 1)",
            "expected": "flood",
            "src_ip":   "10.0.0.99",
            "features": {
                "mqtt.qos": 0, "mqtt.hdrflags": 48,
                "tcp.len": 512, "mqtt.msgtype": 3,
                "mqtt.retain": 0, "tcp.flags": 24,
                "mqtt.msgid": 0, "tcp.time_delta": 0.0001,
            },
        },
        {
            "name":     "Brute Force (Attack 3)",
            "expected": "bruteforce",
            "src_ip":   "10.0.0.99",
            "features": {
                "mqtt.qos": 0, "mqtt.hdrflags": 16,
                "tcp.len": 62, "mqtt.msgtype": 1,
                "mqtt.retain": 0, "tcp.flags": 24,
                "mqtt.msgid": 0, "tcp.time_delta": 0.08,
            },
        },
        {
            "name":     "Slow Drip (Attack 5)",
            "expected": "slowite",
            "src_ip":   "10.0.0.99",
            "features": {
                "mqtt.qos": 0, "mqtt.hdrflags": 48,
                "tcp.len": 45, "mqtt.msgtype": 3,
                "mqtt.retain": 0, "tcp.flags": 24,
                "mqtt.msgid": 0, "tcp.time_delta": 5.2,
            },
        },
        {
            "name":     "Legitimate traffic",
            "expected": "legitimate",
            "src_ip":   "10.0.0.1",
            "features": {
                "mqtt.qos": 1, "mqtt.hdrflags": 50,
                "tcp.len": 85, "mqtt.msgtype": 3,
                "mqtt.retain": 0, "tcp.flags": 24,
                "mqtt.msgid": 1234, "tcp.time_delta": 2.1,
            },
        },
    ]

    print(f"\n{BOLD}[4] Test classify từng loại attack{RESET}")
    passed = 0
    for t in TESTS:
        r = requests.post(
            f"{api}/predict",
            json={"src_ip": t["src_ip"], "features": t["features"], "debug": verbose},
            timeout=5,
        )
        d = r.json()
        label = d.get("label")
        conf  = d.get("confidence", 0)
        rule  = d.get("rule_applied") or ""
        expected = t["expected"]

        if label == expected:
            passed += 1
            ok(f"{t['name']:30s} → {label:12s} conf={conf:.2f} {rule}")
        elif label in {"flood", "dos", "bruteforce", "slowite", "malformed"} and expected != "legitimate":
            warn(f"{t['name']:30s} → {label:12s} (expected {expected}) conf={conf:.2f} — vẫn detect attack")
        else:
            fail(f"{t['name']:30s} → {label:12s} (expected {expected}) conf={conf:.2f}")

        if verbose and "feature_values" in d:
            print(f"    Features: {d['feature_values']}")
            print(f"    All proba: {d.get('all_proba', {})}")

    print(f"\n  Kết quả: {passed}/{len(TESTS)} tests passed")
    return passed == len(TESTS)


def test_simulate(api: str):
    print(f"\n{BOLD}[5] Test /predict/simulate (built-in samples){RESET}")
    for atype in ["flood", "brute", "legit", "slowite", "slow_drip"]:
        r = requests.post(f"{api}/predict/simulate",
                          json={"type": atype}, timeout=5)
        d = r.json()
        label = d.get("label")
        conf  = d.get("confidence", 0)
        rule  = d.get("rule_applied") or ""
        is_atk = d.get("is_attack", False)
        flag = "⚠ ATTACK" if is_atk else "✓ legit"
        info(f"simulate={atype:10s} → {label:12s} conf={conf:.2f}  {flag}  {rule}")


def main():
    parser = argparse.ArgumentParser(description="Test IDS API v3")
    parser.add_argument("--api",     default="http://127.0.0.1:5000")
    parser.add_argument("--verbose", action="store_true",
                        help="In ra feature values và all_proba")
    args = parser.parse_args()

    print(f"\n{'='*55}")
    print(f"{BOLD}  IDS API v3 — Test Suite{RESET}")
    print(f"  Target: {args.api}")
    print(f"{'='*55}")

    try:
        test_health(args.api)
        test_zero_bias(args.api)
        test_feature_parse(args.api, args.verbose)
        all_pass = test_attack_classify(args.api, args.verbose)
        test_simulate(args.api)

        print(f"\n{'='*55}")
        if all_pass:
            print(f"{GREEN}{BOLD}  Tất cả test PASSED ✓{RESET}")
        else:
            print(f"{YELLOW}{BOLD}  Một số test không khớp expected — xem warning ở trên{RESET}")
        print(f"{'='*55}\n")

    except requests.exceptions.ConnectionError:
        print(f"\n{RED}[ERROR] Không kết nối được {args.api}{RESET}")
        print("→ Chạy trước: python3 ids_api.py --model best_model_xgb_v2.pkl ...")
        sys.exit(1)


if __name__ == "__main__":
    main()
