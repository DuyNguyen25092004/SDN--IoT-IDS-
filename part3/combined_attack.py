#!/usr/bin/env python3
"""
combined_attack.py — Realistic multi-stage adversary scenario.

Why combined (not one-by-one)?
------------------------------
A real attacker rarely fires a single, clean attack class at the broker.
The kill-chain typically looks like:
    Recon  →  Credential test  →  Resource exhaustion  →  Stealth exfil
Each stage is a different *class* in the MQTTset taxonomy
(bruteforce, malformed, dos/flood, slowite). A combined script lets us
verify the IDS/SDN reaction under a more realistic, time-overlapped
threat — including:
  * label transitions on a single source IP within one session
  * whether the SDN block at stage N also stops stages N+1..N+M
  * whether the threat-score decay window across stages behaves correctly

This script orchestrates 4 stages on a single attacker host. Each stage
is a child process spawning the existing per-attack scripts in
`part3/`, so the per-attack signatures stay identical to the model's
training distribution — we only schedule them.

Stages (default timing, --profile fast):
    t=0s   Stage A — RECON       : low-rate malformed probe   (5s, ~10 pkt/s)
    t=8s   Stage B — CREDENTIAL  : brute-force CONNECT spam   (until first
                                   block or 12s, delay=0.05s)
    t=22s  Stage C — IMPACT      : MQTT flood / DoS burst     (15s)
    t=40s  Stage D — STEALTH EXFIL: slow-drip publish         (20s, 1.5 msg/s)

The IDS will (and should) block early — usually in Stage A or B. Stage C
and D are still launched so we can confirm the block actually severs
follow-on traffic.

Usage (run inside Mininet from hattacker):
    mininet> hattacker python3 part3/combined_attack.py \
                 --host 10.0.0.10 --profile fast

Profiles:
    fast    : ~60s, aggressive (good for demo + screen recording)
    stealth : ~5min, low-rate everything (tests decay/long-window)
    burst   : all 4 stages launched in parallel (worst-case overlap)

Reset the IDS/Ryu state once before launching:
    curl -s -X POST http://127.0.0.1:5000/reset
    curl -s -X POST http://127.0.0.1:8080/ids/unblock \
         -H 'Content-Type: application/json' -d '{"ip":"10.0.0.99"}'
"""

import argparse
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
PY   = sys.executable

ATTACKS = {
    "malformed":   HERE / "attack4_malformed.py",
    "bruteforce":  HERE / "attack3_brute_force.py",
    "flood":       HERE / "attack1_mqtt_flood.py",
    "dos":         HERE / "attack2_dos.py",
    "slow_drip":   HERE / "attack5_slow_drip.py",
}

PROFILES = {
    # name : list of (delay_s, label, argv)
    "fast": [
        (0,  "RECON   (malformed probe)",
            ["malformed",  "--target", "{host}", "--port", "{port}",
             "--rate", "10", "--duration", "5"]),
        (8,  "CRED    (brute-force CONNECT)",
            ["bruteforce", "--host",   "{host}", "--port", "{port}",
             "--delay", "0.05"]),
        (22, "IMPACT  (MQTT flood)",
            ["flood",      "--host",   "{host}", "--port", "{port}",
             "--threads", "5", "--iter", "60", "--rate", "300"]),
        (40, "EXFIL   (slow-drip)",
            ["slow_drip",  "--host",   "{host}", "--port", "{port}",
             "--rate", "1.5"]),
    ],
    "stealth": [
        (0,   "RECON   (slow malformed)",
            ["malformed",  "--target", "{host}", "--port", "{port}",
             "--rate", "2",  "--duration", "30"]),
        (45,  "CRED    (low-rate brute)",
            ["bruteforce", "--host",   "{host}", "--port", "{port}",
             "--delay", "1.0"]),
        (120, "IMPACT  (small DoS)",
            ["dos",        "--host",   "{host}", "--port", "{port}",
             "--threads", "2"]),
        (210, "EXFIL   (slow-drip)",
            ["slow_drip",  "--host",   "{host}", "--port", "{port}",
             "--rate", "1.0"]),
    ],
    "burst": [
        (0, "RECON   (malformed)",
            ["malformed", "--target", "{host}", "--port", "{port}",
             "--rate", "20", "--duration", "20"]),
        (0, "CRED    (brute)",
            ["bruteforce", "--host",  "{host}", "--port", "{port}",
             "--delay", "0.05"]),
        (0, "IMPACT  (flood)",
            ["flood",     "--host",   "{host}", "--port", "{port}",
             "--threads", "5", "--iter", "60", "--rate", "300"]),
        (0, "EXFIL   (slow-drip)",
            ["slow_drip", "--host",   "{host}", "--port", "{port}",
             "--rate", "1.5"]),
    ],
}


def fmt(args, host, port):
    return [a.format(host=host, port=port) for a in args]


def main():
    ap = argparse.ArgumentParser(description="Multi-stage MQTT adversary")
    ap.add_argument("--host", required=True, help="Broker IP (e.g. 10.0.0.10)")
    ap.add_argument("--port", type=int, default=1883)
    ap.add_argument("--profile", choices=list(PROFILES), default="fast")
    ap.add_argument("--logdir", default="/tmp/combined_attack")
    args = ap.parse_args()

    os.makedirs(args.logdir, exist_ok=True)
    plan = PROFILES[args.profile]

    print("=" * 64)
    print(f"  COMBINED ATTACK  target={args.host}:{args.port}  profile={args.profile}")
    print(f"  stages={len(plan)}   logs={args.logdir}/")
    print("=" * 64)

    started = []
    t0 = time.time()
    try:
        for delay, label, argv in plan:
            wait = (t0 + delay) - time.time()
            if wait > 0:
                time.sleep(wait)
            attack = argv[0]
            script = ATTACKS[attack]
            cmdargs = fmt(argv[1:], args.host, args.port)
            cmd = [PY, str(script), *cmdargs]
            log = open(f"{args.logdir}/stage_{len(started):02d}_{attack}.log", "w")
            print(f"[{time.time()-t0:6.1f}s] LAUNCH {label:<32}  →  {' '.join(cmdargs)}")
            p = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT)
            started.append((label, p, log))

        # Wait for all to finish (they self-terminate or get blocked)
        for label, p, log in started:
            p.wait()
            log.close()
            print(f"[{time.time()-t0:6.1f}s] DONE   {label}  rc={p.returncode}")

    except KeyboardInterrupt:
        print("\n[!] Interrupted — terminating children...")
        for _, p, _ in started:
            try:
                p.send_signal(signal.SIGINT)
            except Exception:
                pass

    print("=" * 64)
    print(f"  COMPLETED in {time.time()-t0:.1f}s. Inspect IDS log + /ids/rules.")
    print("=" * 64)


if __name__ == "__main__":
    main()
