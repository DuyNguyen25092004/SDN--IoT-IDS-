#!/usr/bin/env python3
"""
scenario_multi_attacker.py — Kịch bản 2: 2 Attacker IP khác nhau, đồng thời
=============================================================================
Chạy từ Mininet CLI trên HOST machine (không phải trong namespace):
    sudo python3 scenario_multi_attacker.py --host 10.0.0.10

Hoặc chạy từ Mininet CLI với lệnh 2 dòng:
    mininet> hattacker python3 scenario_multi_attacker.py --host 10.0.0.10 &
    (script sẽ tự điều phối cả h4 qua Mininet API)

Cách hoạt động:
  - hattacker (10.0.0.99): chạy các attack nặng (flood, dos)
  - h4         (10.0.0.4) : chạy các attack khác (brute, malformed, slowdrip)
  - Script điều phối qua subprocess, mỗi host chạy trong namespace riêng
    bằng 'ip netns exec' hoặc 'mnexec' nếu có.

Lưu ý: Script này cần chạy với quyền sudo từ HOST (không phải trong Mininet CLI)
để có thể dùng ip netns exec / mnexec điều phối đa namespace.

Chạy từ host:
    sudo python3 scenario_multi_attacker.py --host 10.0.0.10 --combo A
"""

import subprocess
import threading
import time
import json
import urllib.request
import argparse
import logging
import sys
import os

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(threadName)-20s] %(message)s"
)
log = logging.getLogger("Scenario2")

# ── Cấu hình 2 attacker ───────────────────────────────────────────────────────
ATTACKER1_IP   = "10.0.0.99"   # hattacker — attack nặng
ATTACKER2_IP   = "10.0.0.4"    # h4 (publisher bị chiếm) — attack khác loại
ATTACKER1_HOST = "hattacker"   # Mininet host name
ATTACKER2_HOST = "h4"

IDS_IP   = "10.0.0.10"
IDS_PORT = 5000
RYU_IP   = "127.0.0.1"
RYU_PORT = 8080

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def call_api(ip, port, path, body):
    url = f"http://{ip}:{port}{path}"
    try:
        data = json.dumps(body).encode()
        req  = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=4.0) as r:
            return json.loads(r.read())
    except Exception as e:
        log.warning(f"  API {url}: {e}")
        return None


def ryu_block_op(op, ip):
    """Gọi Ryu block/unblock — chạy trực tiếp trên host (không qua namespace)."""
    try:
        r = urllib.request.urlopen(
            urllib.request.Request(
                f"http://{RYU_IP}:{RYU_PORT}/ids/{op}",
                data=json.dumps({"ip": ip}).encode(),
                method="POST",
                headers={"Content-Type": "application/json"},
            ), timeout=4
        )
        log.info(f"  Ryu {op} {ip}: {r.read().decode()[:60]}")
    except Exception as e:
        log.warning(f"  Ryu {op} {ip}: {e}")


def reset_attacker(attacker_ip):
    """Reset IDS state cho 1 IP."""
    call_api(IDS_IP, IDS_PORT, "/unblock", {"ip": attacker_ip})
    ryu_block_op("unblock", attacker_ip)


def reset_all():
    """Reset cả 2 attacker."""
    log.info("  ♻️  Reset state cho cả 2 attacker...")
    reset_attacker(ATTACKER1_IP)
    reset_attacker(ATTACKER2_IP)
    time.sleep(3)
    log.info("  ✅ Sẵn sàng.\n")


def run_in_namespace(mininet_host, cmd_args, label, results):
    """
    Chạy lệnh trong network namespace của Mininet host.
    Dùng 'ip netns exec <host>' hoặc 'mnexec -a <pid>'.
    """
    # Cách 1: ip netns exec (Mininet tạo netns với tên = host name)
    full_cmd = ["ip", "netns", "exec", mininet_host, sys.executable] + cmd_args

    log.info(f"  [{label}] Chạy trong ns={mininet_host}: {' '.join(cmd_args[:3])}...")
    start = time.time()
    try:
        proc = subprocess.run(
            full_cmd,
            capture_output=True, text=True,
            cwd=SCRIPT_DIR,
        )
        elapsed = round(time.time() - start, 1)
        results[label] = {"ok": proc.returncode == 0, "elapsed": elapsed,
                          "exit": proc.returncode}
        status = "✅" if proc.returncode == 0 else "⚠️"
        log.info(f"  [{label}] {status} Xong sau {elapsed}s (exit={proc.returncode})")
        if proc.returncode != 0 and proc.stderr:
            log.warning(f"  [{label}] stderr: {proc.stderr[:200]}")
    except Exception as e:
        results[label] = {"ok": False, "elapsed": 0, "exit": -1, "error": str(e)}
        log.error(f"  [{label}] Lỗi: {e}")


# ── Định nghĩa các combo ──────────────────────────────────────────────────────

def get_combos(host, port):
    p = str(port)
    return {
        # Combo A: Attacker1 tấn công DoS, Attacker2 tấn công BruteForce
        "A": {
            "name": "A1:DoS  vs  A2:BruteForce",
            "desc": "2 vector khác loại, cùng lúc",
            "jobs": [
                (ATTACKER1_HOST, ATTACKER1_IP, "A1-DoS",
                 ["attack2_dos.py", "--host", host, "--port", p,
                  "--threads", "4", "--iter", "400"]),
                (ATTACKER2_HOST, ATTACKER2_IP, "A2-BruteForce",
                 ["attack3_brute_force.py", "--host", host, "--port", p,
                  "--delay", "0.4"]),
            ],
        },
        # Combo B: Attacker1 tấn công Flood, Attacker2 tấn công Malformed
        "B": {
            "name": "A1:Flood  vs  A2:Malformed",
            "desc": "Flood mạnh + Malformed cùng lúc",
            "jobs": [
                (ATTACKER1_HOST, ATTACKER1_IP, "A1-Flood",
                 ["attack1_mqtt_flood.py", "--host", host, "--port", p,
                  "--threads", "4", "--iter", "3"]),
                (ATTACKER2_HOST, ATTACKER2_IP, "A2-Malformed",
                 ["attack4_malformed.py", "--target", host, "--port", p,
                  "--rate", "40", "--duration", "25"]),
            ],
        },
        # Combo C: Attacker1 tấn công DoS, Attacker2 tấn công SlowDrip
        "C": {
            "name": "A1:DoS  vs  A2:SlowDrip",
            "desc": "Tấn công nhanh + tấn công ẩn cùng lúc",
            "jobs": [
                (ATTACKER1_HOST, ATTACKER1_IP, "A1-DoS",
                 ["attack2_dos.py", "--host", host, "--port", p,
                  "--threads", "4", "--iter", "400"]),
                (ATTACKER2_HOST, ATTACKER2_IP, "A2-SlowDrip",
                 ["attack5_slow_drip.py", "--host", host, "--port", p,
                  "--rate", "1.2"]),
            ],
        },
        # Combo D: Cả 3 loại từ 2 attacker (A1 chạy 2 attack tuần tự, A2 chạy 1)
        "D": {
            "name": "A1:Flood+DoS  vs  A2:Malformed+Brute",
            "desc": "Mỗi attacker chạy 2 loại tuần tự, 2 attacker song song",
            "jobs": [
                (ATTACKER1_HOST, ATTACKER1_IP, "A1-Flood",
                 ["attack1_mqtt_flood.py", "--host", host, "--port", p,
                  "--threads", "3", "--iter", "2"]),
                (ATTACKER2_HOST, ATTACKER2_IP, "A2-Malformed",
                 ["attack4_malformed.py", "--target", host, "--port", p,
                  "--rate", "30", "--duration", "20"]),
            ],
        },
    }


def run_combo(combo, rounds=1):
    name = combo["name"]
    jobs = combo["jobs"]

    for rnd in range(1, rounds + 1):
        log.info("\n" + "=" * 60)
        log.info(f"  ROUND {rnd}/{rounds}: {name}")
        log.info(f"  {combo['desc']}")
        log.info(f"  Attackers: {[j[2] for j in jobs]}")
        log.info("=" * 60)

        reset_all()

        results = {}
        threads = []
        for (mn_host, attacker_ip, label, cmd_args) in jobs:
            t = threading.Thread(
                target=run_in_namespace,
                args=(mn_host, cmd_args, label, results),
                name=label,
                daemon=True,
            )
            threads.append(t)

        # Phóng tất cả thread cùng lúc
        for t in threads:
            t.start()
            time.sleep(0.5)   # stagger nhỏ

        for t in threads:
            t.join(timeout=300)

        log.info(f"\n  📊 KẾT QUẢ ROUND {rnd}:")
        for label, res in results.items():
            s = "✅" if res.get("ok") else "⚠️"
            log.info(f"    {s} {label}: {res.get('elapsed')}s, exit={res.get('exit')}")

        if rnd < rounds:
            log.info("\n  ⏳ Nghỉ 20s trước round tiếp...")
            time.sleep(20)

    log.info("\n" + "=" * 60)
    log.info("  🏁 HOÀN THÀNH!")
    log.info("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Combo:
  A — A1:DoS           vs A2:BruteForce    (khác loại hoàn toàn)
  B — A1:Flood         vs A2:Malformed     (flood mạnh + malformed)
  C — A1:DoS           vs A2:SlowDrip      (nhanh vs ẩn)
  D — A1:Flood         vs A2:Malformed     (multi-wave)

Chạy từ HOST (sudo), không phải trong Mininet CLI:
  sudo python3 scenario_multi_attacker.py --host 10.0.0.10 --combo A
        """
    )
    parser.add_argument("--host",   default="10.0.0.10")
    parser.add_argument("--port",   type=int, default=1883)
    parser.add_argument("--combo",  default="A", choices=["A","B","C","D"])
    parser.add_argument("--rounds", type=int, default=1)
    parser.add_argument("--ids-ip", default="10.0.0.10")
    parser.add_argument("--ryu-ip", default="127.0.0.1")
    args = parser.parse_args()

    global IDS_IP, RYU_IP
    IDS_IP = args.ids_ip
    RYU_IP = args.ryu_ip

    combos = get_combos(args.host, args.port)
    combo  = combos[args.combo]

    log.info("\n" + "=" * 60)
    log.info("  🎯 KỊCH BẢN 2: MULTI-ATTACKER ĐỒNG THỜI")
    log.info(f"  Combo  : [{args.combo}] {combo['name']}")
    log.info(f"  Rounds : {args.rounds}")
    log.info(f"  A1 IP  : {ATTACKER1_IP} ({ATTACKER1_HOST})")
    log.info(f"  A2 IP  : {ATTACKER2_IP} ({ATTACKER2_HOST})")
    log.info(f"  Target : {args.host}:{args.port}")
    log.info("=" * 60)

    run_combo(combo, args.rounds)


if __name__ == "__main__":
    main()