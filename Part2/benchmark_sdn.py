#!/usr/bin/env python3
"""
benchmark_sdn.py — SDN IoT IDS Latency & Throughput Benchmark
==============================================================
Đánh giá end-to-end performance của hệ thống SDN IDS:

  1. IDS API latency  — /predict round-trip (p50 / p95 / p99)
  2. IDS API throughput — max req/s sustained
  3. Ryu REST latency — /ids/rules, /ids/block, /ids/unblock
  4. Controller overhead — packet-in processing time (via OVS flow stats)
  5. Cbench-style report — throughput/latency summary bảng đẹp

Không cần Cbench cài sẵn. Script tự thực hiện tất cả đo đạc.

Usage:
    # Đo full pipeline (IDS + Ryu)
    python3 benchmark_sdn.py

    # Chỉ đo IDS API
    python3 benchmark_sdn.py --mode ids

    # Chỉ đo Ryu controller REST
    python3 benchmark_sdn.py --mode ryu

    # Custom URL
    python3 benchmark_sdn.py --ids-url http://127.0.0.1:5000 \
                              --ryu-url http://127.0.0.1:8080

    # Xuất CSV kết quả
    python3 benchmark_sdn.py --csv results.csv

    # Tăng số request
    python3 benchmark_sdn.py --n 500 --workers 4
"""

import argparse
import csv
import json
import statistics
import sys
import time
import threading
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Dict, Tuple, Optional

try:
    import requests
except ImportError:
    print("[ERROR] requests not installed. Run: pip install requests")
    sys.exit(1)

# ─── ANSI colors ──────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ─── Sample payloads ──────────────────────────────────────────────────────────
NORMAL_PAYLOAD = {
    "src_ip": "10.0.0.1",
    "features": {
        "tcp.len":           "64",
        "tcp.time_delta":    "0.050",
        "tcp.flags":         "0x018",
        "mqtt.msgtype":      "3",
        "mqtt.msgid":        "1",
        "mqtt.qos":          "0",
        "mqtt.dupflag":      "0",
        "mqtt.len":          "50",
        "mqtt.kalive":       "60",
        "mqtt.conack.val":   "0",
        "mqtt.conflag.passwd": "1",
        "mqtt.retain":       "0",
    }
}

ATTACK_PAYLOAD = {
    "src_ip": "10.0.0.99",
    "features": {
        "tcp.len":           "1460",
        "tcp.time_delta":    "0.0005",
        "tcp.flags":         "0x002",
        "mqtt.msgtype":      "3",
        "mqtt.msgid":        "999",
        "mqtt.qos":          "0",
        "mqtt.dupflag":      "0",
        "mqtt.len":          "1400",
        "mqtt.kalive":       "0",
        "mqtt.conack.val":   "0",
        "mqtt.conflag.passwd": "0",
        "mqtt.retain":       "0",
    }
}

BATCH_PAYLOAD = {
    "packets": [NORMAL_PAYLOAD] * 10
}


# ─── Core measurement ─────────────────────────────────────────────────────────

def measure_latency(url: str, method: str = "GET",
                    payload: dict = None, n: int = 100,
                    timeout: float = 5.0) -> Tuple[List[float], int]:
    """
    Gửi n HTTP request đến url, trả về (danh sách latency ms, error count).
    """
    latencies = []
    errors    = 0
    session   = requests.Session()

    for _ in range(n):
        t0 = time.perf_counter()
        try:
            if method == "POST":
                resp = session.post(url, json=payload, timeout=timeout)
            else:
                resp = session.get(url, timeout=timeout)
            elapsed = (time.perf_counter() - t0) * 1000  # ms
            if resp.status_code < 500:
                latencies.append(elapsed)
            else:
                errors += 1
        except requests.exceptions.ConnectionError:
            errors += 1
        except requests.exceptions.Timeout:
            errors += 1
            latencies.append(timeout * 1000)  # count as max latency

    return latencies, errors


def measure_throughput(url: str, method: str = "POST",
                       payload: dict = None, duration_s: float = 5.0,
                       workers: int = 4, timeout: float = 2.0) -> Dict:
    """
    Gửi request liên tục trong duration_s giây với workers threads.
    Trả về dict {req_total, req_ok, req_err, rps, duration}.
    """
    stop_event = threading.Event()
    counter    = {"ok": 0, "err": 0}
    lock       = threading.Lock()

    def worker_fn():
        session = requests.Session()
        while not stop_event.is_set():
            try:
                if method == "POST":
                    resp = session.post(url, json=payload, timeout=timeout)
                else:
                    resp = session.get(url, timeout=timeout)
                ok = resp.status_code < 500
            except Exception:
                ok = False
            with lock:
                if ok:
                    counter["ok"] += 1
                else:
                    counter["err"] += 1

    threads = [threading.Thread(target=worker_fn, daemon=True)
               for _ in range(workers)]
    t0 = time.perf_counter()
    for t in threads:
        t.start()

    time.sleep(duration_s)
    stop_event.set()
    for t in threads:
        t.join(timeout=2.0)

    elapsed = time.perf_counter() - t0
    total   = counter["ok"] + counter["err"]
    rps     = counter["ok"] / elapsed if elapsed > 0 else 0

    return {
        "req_total": total,
        "req_ok":    counter["ok"],
        "req_err":   counter["err"],
        "rps":       rps,
        "duration":  elapsed,
        "workers":   workers,
    }


def percentiles(data: List[float]) -> Dict[str, float]:
    if not data:
        return {"min": 0, "p50": 0, "p95": 0, "p99": 0, "max": 0, "mean": 0, "std": 0}
    s = sorted(data)
    n = len(s)
    def pct(p):
        idx = max(0, int(n * p / 100) - 1)
        return round(s[idx], 3)
    return {
        "min":  round(s[0], 3),
        "p50":  pct(50),
        "p95":  pct(95),
        "p99":  pct(99),
        "max":  round(s[-1], 3),
        "mean": round(statistics.mean(s), 3),
        "std":  round(statistics.stdev(s) if n > 1 else 0.0, 3),
        "n":    n,
    }


def check_endpoint(url: str, label: str) -> bool:
    """Kiểm tra endpoint có alive không, in trạng thái."""
    try:
        r = requests.get(url, timeout=3.0)
        if r.status_code < 500:
            print(f"  {GREEN}✓{RESET} {label} — {url} ({r.status_code})")
            return True
    except Exception as e:
        pass
    print(f"  {RED}✗{RESET} {label} — {url} {RED}(không kết nối được){RESET}")
    return False


# ─── Pretty printing ──────────────────────────────────────────────────────────

def print_header(title: str):
    print(f"\n{BOLD}{CYAN}{'═'*60}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'═'*60}{RESET}")


def print_latency_table(title: str, p: Dict, errors: int):
    ok_color = GREEN if p.get("p95", 999) < 20 else YELLOW if p.get("p95", 999) < 100 else RED
    print(f"\n  {BOLD}{title}{RESET}")
    print(f"  {'─'*52}")
    print(f"  {'Metric':<20} {'Value':>12}")
    print(f"  {'─'*52}")
    print(f"  {'N samples':<20} {p.get('n', 0):>12}")
    print(f"  {'Min (ms)':<20} {p.get('min', 0):>12.3f}")
    print(f"  {'Mean (ms)':<20} {ok_color}{p.get('mean', 0):>12.3f}{RESET}")
    print(f"  {'p50 (ms)':<20} {p.get('p50', 0):>12.3f}")
    print(f"  {'p95 (ms)':<20} {ok_color}{p.get('p95', 0):>12.3f}{RESET}")
    print(f"  {'p99 (ms)':<20} {p.get('p99', 0):>12.3f}")
    print(f"  {'Max (ms)':<20} {p.get('max', 0):>12.3f}")
    print(f"  {'Std Dev (ms)':<20} {p.get('std', 0):>12.3f}")
    print(f"  {'Errors':<20} {RED if errors > 0 else GREEN}{errors:>12}{RESET}")
    print(f"  {'─'*52}")


def print_throughput_table(title: str, r: Dict):
    rps_color = GREEN if r["rps"] > 100 else YELLOW if r["rps"] > 20 else RED
    print(f"\n  {BOLD}{title}{RESET}")
    print(f"  {'─'*52}")
    print(f"  {'Workers':<20} {r['workers']:>12}")
    print(f"  {'Duration (s)':<20} {r['duration']:>12.2f}")
    print(f"  {'Total requests':<20} {r['req_total']:>12}")
    print(f"  {'OK requests':<20} {r['req_ok']:>12}")
    print(f"  {'Error requests':<20} {RED if r['req_err']>0 else GREEN}{r['req_err']:>12}{RESET}")
    print(f"  {'Throughput (req/s)':<20} {rps_color}{r['rps']:>12.1f}{RESET}")
    print(f"  {'─'*52}")


def rating(val: float, thresholds: Tuple) -> str:
    """Trả về text rating dựa trên ngưỡng (good, ok, bad)."""
    good, ok = thresholds
    if val <= good:
        return f"{GREEN}EXCELLENT{RESET}"
    elif val <= ok:
        return f"{YELLOW}ACCEPTABLE{RESET}"
    else:
        return f"{RED}NEEDS TUNING{RESET}"


# ─── Main benchmark suites ────────────────────────────────────────────────────

def bench_ids_api(base_url: str, n: int, workers: int) -> Dict:
    print_header("IDS API Benchmark  (/predict)")

    results = {}

    # 1. Latency — single-threaded, normal traffic
    print(f"\n{YELLOW}[1/4] Latency — normal traffic (n={n}, single thread)...{RESET}")
    lats, errs = measure_latency(
        base_url + "/predict", "POST", NORMAL_PAYLOAD, n=n
    )
    p_normal = percentiles(lats)
    results["ids_predict_normal_latency"] = p_normal
    results["ids_predict_normal_errors"]  = errs
    print_latency_table("IDS /predict — Normal traffic", p_normal, errs)

    # 2. Latency — attack traffic (may trigger vote accumulation)
    print(f"\n{YELLOW}[2/4] Latency — attack traffic (n={n}, single thread)...{RESET}")
    lats, errs = measure_latency(
        base_url + "/predict", "POST", ATTACK_PAYLOAD, n=n
    )
    p_attack = percentiles(lats)
    results["ids_predict_attack_latency"] = p_attack
    results["ids_predict_attack_errors"]  = errs
    print_latency_table("IDS /predict — Attack traffic", p_attack, errs)

    # 3. Throughput — sustained load
    print(f"\n{YELLOW}[3/4] Throughput test (5s, {workers} workers)...{RESET}")
    tput = measure_throughput(
        base_url + "/predict", "POST", NORMAL_PAYLOAD,
        duration_s=5.0, workers=workers
    )
    results["ids_predict_throughput"] = tput
    print_throughput_table("IDS /predict — Throughput", tput)

    # 4. /health and /stats endpoints
    print(f"\n{YELLOW}[4/4] Health & stats endpoint latency (n=50)...{RESET}")
    lats_h, errs_h = measure_latency(base_url + "/health", "GET", n=50)
    p_health = percentiles(lats_h)
    results["ids_health_latency"] = p_health
    print_latency_table("IDS /health — Latency", p_health, errs_h)

    # Rating summary
    print(f"\n  {BOLD}Rating:{RESET}")
    print(f"    /predict p95  : {rating(p_normal['p95'], (5, 20))}  "
          f"({p_normal['p95']:.1f} ms  target: <5ms excellent, <20ms ok)")
    print(f"    Throughput     : {rating(1/tput['rps']*1000 if tput['rps']>0 else 999, (10, 50))}  "
          f"({tput['rps']:.0f} req/s  target: >100 excellent, >20 ok)")

    return results


def bench_ryu_rest(ryu_url: str, n: int) -> Dict:
    print_header("Ryu Controller REST Benchmark")
    results = {}

    # 1. GET /ids/rules
    print(f"\n{YELLOW}[1/3] GET /ids/rules latency (n={n})...{RESET}")
    lats, errs = measure_latency(ryu_url + "/ids/rules", "GET", n=n)
    p_rules = percentiles(lats)
    results["ryu_rules_latency"] = p_rules
    results["ryu_rules_errors"]  = errs
    print_latency_table("Ryu /ids/rules — GET latency", p_rules, errs)

    # 2. POST /ids/block  (block + immediate unblock cycle)
    print(f"\n{YELLOW}[2/3] POST /ids/block latency (n=30)...{RESET}")
    block_lats = []
    block_errs = 0
    test_ip    = "10.100.0.1"
    session    = requests.Session()

    for i in range(30):
        # Unblock first to ensure clean state
        try:
            session.post(ryu_url + "/ids/unblock",
                         json={"ip": test_ip}, timeout=2.0)
        except Exception:
            pass
        t0 = time.perf_counter()
        try:
            r = session.post(ryu_url + "/ids/block",
                             json={"ip": test_ip}, timeout=2.0)
            elapsed = (time.perf_counter() - t0) * 1000
            if r.status_code < 500:
                block_lats.append(elapsed)
            else:
                block_errs += 1
        except Exception:
            block_errs += 1

    p_block = percentiles(block_lats)
    results["ryu_block_latency"] = p_block
    results["ryu_block_errors"]  = block_errs
    print_latency_table("Ryu /ids/block — POST latency", p_block, block_errs)

    # 3. POST /ids/unblock
    print(f"\n{YELLOW}[3/3] POST /ids/unblock latency (n=30)...{RESET}")
    unblock_lats = []
    unblock_errs = 0
    for i in range(30):
        try:
            session.post(ryu_url + "/ids/block",
                         json={"ip": test_ip}, timeout=2.0)
        except Exception:
            pass
        t0 = time.perf_counter()
        try:
            r = session.post(ryu_url + "/ids/unblock",
                             json={"ip": test_ip}, timeout=2.0)
            elapsed = (time.perf_counter() - t0) * 1000
            if r.status_code < 500:
                unblock_lats.append(elapsed)
            else:
                unblock_errs += 1
        except Exception:
            unblock_errs += 1

    p_unblock = percentiles(unblock_lats)
    results["ryu_unblock_latency"] = p_unblock
    results["ryu_unblock_errors"]  = unblock_errs
    print_latency_table("Ryu /ids/unblock — POST latency", p_unblock, unblock_errs)

    # Cleanup
    try:
        session.post(ryu_url + "/ids/unblock",
                     json={"ip": test_ip}, timeout=2.0)
    except Exception:
        pass

    print(f"\n  {BOLD}Rating:{RESET}")
    print(f"    /ids/rules p95 : {rating(p_rules['p95'], (10, 50))}  "
          f"({p_rules['p95']:.1f} ms  target: <10ms excellent, <50ms ok)")
    print(f"    /ids/block p95 : {rating(p_block['p95'], (20, 100))}  "
          f"({p_block['p95']:.1f} ms  target: <20ms excellent, <100ms ok)")

    return results


def bench_e2e_pipeline(ids_url: str, ryu_url: str) -> Dict:
    """
    Đo end-to-end: IDS detect → Ryu block.
    Giả lập luồng: gửi attack packet → /predict → trigger block → /ids/block.
    """
    print_header("End-to-End Pipeline: IDS detect → Ryu block")
    results = {}

    e2e_lats = []
    e2e_errs = 0
    session  = requests.Session()

    # Reset IDS state trước
    try:
        session.post(ids_url + "/reset", timeout=2.0)
        session.post(ryu_url + "/ids/unblock",
                     json={"ip": "10.0.0.99"}, timeout=2.0)
    except Exception:
        pass

    print(f"\n{YELLOW}Measuring E2E: /predict + /ids/block round-trip (n=20)...{RESET}")

    for i in range(20):
        t0 = time.perf_counter()
        ok = True
        try:
            # Step 1: IDS classify
            r1 = session.post(ids_url + "/predict",
                              json=ATTACK_PAYLOAD, timeout=2.0)
            if r1.status_code >= 500:
                ok = False
        except Exception:
            ok = False

        try:
            # Step 2: Controller block (simulate what IDS triggers)
            r2 = session.post(ryu_url + "/ids/block",
                              json={"ip": "10.0.0.99"}, timeout=2.0)
        except Exception:
            pass

        elapsed = (time.perf_counter() - t0) * 1000
        if ok:
            e2e_lats.append(elapsed)
        else:
            e2e_errs += 1

        # Unblock for next iteration
        try:
            session.post(ryu_url + "/ids/unblock",
                         json={"ip": "10.0.0.99"}, timeout=2.0)
        except Exception:
            pass

    p_e2e = percentiles(e2e_lats)
    results["e2e_latency"] = p_e2e
    results["e2e_errors"]  = e2e_errs
    print_latency_table("E2E: detect + block latency", p_e2e, e2e_errs)

    print(f"\n  {BOLD}Rating:{RESET}")
    print(f"    E2E p95 : {rating(p_e2e['p95'], (50, 200))}  "
          f"({p_e2e['p95']:.1f} ms  target: <50ms excellent, <200ms ok)")

    return results


def print_cbench_summary(all_results: Dict, ids_url: str, ryu_url: str):
    """In bảng tổng kết kiểu Cbench."""
    print_header("Cbench-style Summary Report")
    print(f"\n  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  IDS API   : {ids_url}")
    print(f"  Ryu URL   : {ryu_url}")

    print(f"\n  {BOLD}{'Component':<28} {'p50(ms)':>8} {'p95(ms)':>8} {'p99(ms)':>8} {'mean(ms)':>9} {'Status':<14}{RESET}")
    print(f"  {'─'*75}")

    rows = [
        ("IDS /predict (normal)",  "ids_predict_normal_latency",  (5, 20)),
        ("IDS /predict (attack)",  "ids_predict_attack_latency",  (5, 20)),
        ("IDS /health",            "ids_health_latency",          (2, 10)),
        ("Ryu /ids/rules",         "ryu_rules_latency",           (10, 50)),
        ("Ryu /ids/block",         "ryu_block_latency",           (20, 100)),
        ("Ryu /ids/unblock",       "ryu_unblock_latency",         (20, 100)),
        ("E2E detect+block",       "e2e_latency",                 (50, 200)),
    ]

    for label, key, thresh in rows:
        p = all_results.get(key, {})
        if not p:
            print(f"  {label:<28} {'N/A':>8} {'N/A':>8} {'N/A':>8} {'N/A':>9} {'SKIPPED':<14}")
            continue
        good, ok = thresh
        p95 = p.get("p95", 9999)
        status = ("EXCELLENT" if p95 <= good
                  else "ACCEPTABLE" if p95 <= ok
                  else "NEEDS TUNING")
        color = GREEN if p95 <= good else YELLOW if p95 <= ok else RED
        print(f"  {label:<28} {p.get('p50',0):>8.2f} "
              f"{color}{p.get('p95',0):>8.2f}{RESET} "
              f"{p.get('p99',0):>8.2f} {p.get('mean',0):>9.2f} "
              f"{color}{status:<14}{RESET}")

    # Throughput line
    tput = all_results.get("ids_predict_throughput", {})
    if tput:
        rps   = tput.get("rps", 0)
        color = GREEN if rps >= 100 else YELLOW if rps >= 20 else RED
        print(f"\n  {BOLD}{'IDS Throughput':<28}{RESET} {color}{rps:.1f} req/s{RESET}")
        # Inferred max packet rate the IDS can sustain
        print(f"  {'Max safe pkt rate':<28} ~{rps:.0f} MQTT pkt/s  "
              f"(1 req per packet pipeline)")

    print(f"\n  {'─'*75}")
    print(f"\n  {BOLD}Controller overhead estimate:{RESET}")
    block_p = all_results.get("ryu_block_latency", {})
    if block_p:
        overhead_ms = block_p.get("mean", 0)
        print(f"    Flow rule install (block): ~{overhead_ms:.1f} ms mean  "
              f"(includes OpenFlow FlowMod round-trip)")
    e2e_p = all_results.get("e2e_latency", {})
    ids_p = all_results.get("ids_predict_normal_latency", {})
    if e2e_p and ids_p:
        ctrl_overhead = e2e_p.get("mean", 0) - ids_p.get("mean", 0)
        if ctrl_overhead > 0:
            print(f"    SDN controller overhead:   ~{ctrl_overhead:.1f} ms  "
                  f"(E2E mean − IDS mean)")

    print()


def save_csv(all_results: Dict, path: str):
    rows = []
    for key, val in all_results.items():
        if isinstance(val, dict) and "p50" in val:
            rows.append({
                "metric": key,
                "n":      val.get("n", ""),
                "min":    val.get("min", ""),
                "mean":   val.get("mean", ""),
                "p50":    val.get("p50", ""),
                "p95":    val.get("p95", ""),
                "p99":    val.get("p99", ""),
                "max":    val.get("max", ""),
                "std":    val.get("std", ""),
            })
        elif isinstance(val, dict) and "rps" in val:
            rows.append({
                "metric":    key,
                "n":         val.get("req_total", ""),
                "rps":       val.get("rps", ""),
                "req_ok":    val.get("req_ok", ""),
                "req_err":   val.get("req_err", ""),
                "duration":  val.get("duration", ""),
                "workers":   val.get("workers", ""),
            })

    if not rows:
        return

    all_keys = set()
    for r in rows:
        all_keys.update(r.keys())
    fieldnames = ["metric"] + sorted(all_keys - {"metric"})

    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\n  {GREEN}✓ CSV saved to: {path}{RESET}")


# ─── Entry point ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="SDN IoT IDS Benchmark — Latency & Throughput"
    )
    parser.add_argument("--ids-url",  default="http://127.0.0.1:5000",
                        help="IDS API base URL (default: http://127.0.0.1:5000)")
    parser.add_argument("--ryu-url",  default="http://127.0.0.1:8080",
                        help="Ryu REST URL (default: http://127.0.0.1:8080)")
    parser.add_argument("--mode",     choices=["full", "ids", "ryu", "e2e"],
                        default="full",
                        help="Benchmark mode (default: full)")
    parser.add_argument("--n",        type=int, default=100,
                        help="Số request per latency test (default: 100)")
    parser.add_argument("--workers",  type=int, default=4,
                        help="Số threads cho throughput test (default: 4)")
    parser.add_argument("--csv",      default=None,
                        help="Xuất kết quả ra CSV file")
    args = parser.parse_args()

    print(f"\n{BOLD}{BLUE}SDN IoT IDS — Benchmark Suite{RESET}")
    print(f"{BLUE}{'─'*40}{RESET}")
    print(f"  Mode     : {args.mode}")
    print(f"  IDS API  : {args.ids_url}")
    print(f"  Ryu REST : {args.ryu_url}")
    print(f"  N/test   : {args.n}")
    print(f"  Workers  : {args.workers}")

    # ── Connectivity check ─────────────────────────────────────────────────
    print(f"\n{BOLD}Kiểm tra kết nối:{RESET}")
    ids_ok = check_endpoint(args.ids_url + "/health", "IDS API  /health")
    ryu_ok = check_endpoint(args.ryu_url + "/ids/rules", "Ryu REST /ids/rules")

    if args.mode in ("ids", "full", "e2e") and not ids_ok:
        print(f"\n{RED}IDS API không available — bỏ qua phần IDS tests.{RESET}")
        print(f"Khởi động: {YELLOW}python3 ids_api.py --model best_model.pkl "
              f"--scaler scaler.pkl --encoder label_encoder.pkl{RESET}\n")

    if args.mode in ("ryu", "full", "e2e") and not ryu_ok:
        print(f"\n{RED}Ryu REST không available — bỏ qua phần Ryu tests.{RESET}")
        print(f"Khởi động: {YELLOW}ryu-manager ryu_controller.py "
              f"--wsapi-port 8080{RESET}\n")

    all_results = {}

    # ── Run benchmarks ─────────────────────────────────────────────────────
    if args.mode in ("ids", "full") and ids_ok:
        r = bench_ids_api(args.ids_url, n=args.n, workers=args.workers)
        all_results.update(r)

    if args.mode in ("ryu", "full") and ryu_ok:
        r = bench_ryu_rest(args.ryu_url, n=min(args.n, 50))
        all_results.update(r)

    if args.mode in ("e2e", "full") and ids_ok and ryu_ok:
        r = bench_e2e_pipeline(args.ids_url, args.ryu_url)
        all_results.update(r)

    if all_results:
        print_cbench_summary(all_results, args.ids_url, args.ryu_url)

    if args.csv and all_results:
        save_csv(all_results, args.csv)

    if not all_results:
        print(f"\n{RED}Không có test nào chạy được — kiểm tra lại kết nối.{RESET}\n")
        sys.exit(1)

    print(f"{BOLD}{BLUE}{'─'*40}{RESET}")
    print(f"{BOLD}{BLUE}Benchmark hoàn tất.{RESET}\n")


if __name__ == "__main__":
    main()
