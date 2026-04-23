#!/usr/bin/env python3
"""
Mininet Topology — Mạng IoT với MQTT Broker
Dành cho Người 3 chạy tất cả attack scripts trong môi trường Mininet.

Topology:
  h1 (MQTT Broker / Mosquitto) — 10.0.0.1
  h2 (IoT sensor bình thường)  — 10.0.0.2
  h3 (IoT sensor bình thường)  — 10.0.0.3
  h4 (Thiết bị bị compromise)  — 10.0.0.4  ← attacker chạy từ đây
  h5 (IoT sensor bình thường)  — 10.0.0.5
  s1 (OVS Switch OpenFlow 1.3)
  Controller: Ryu (remote, port 6633)

Chạy (cần sudo):
  sudo python3 mininet_topology.py

Sau khi topology lên, dùng lệnh trong CLI:
  mininet> h4 python3 attack1_mqtt_flood.py --broker 10.0.0.1 &
  mininet> h4 python3 attack2_c2_malware.py --mode client --broker 10.0.0.1 &
  mininet> h4 python3 attack3_bruteforce.py --broker 10.0.0.1 &
  mininet> h4 python3 attack4_port_scan.py --target 10.0.0.0/24 &
  mininet> h4 python3 attack5_slow_drip.py --broker 10.0.0.1 &
  mininet> h2 python3 normal_traffic.py --broker 10.0.0.1 &
"""

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import time, os, subprocess


def build_topology():
    setLogLevel("info")

    net = Mininet(
        controller=RemoteController,
        switch=OVSKernelSwitch,
        link=TCLink,
        autoSetMacs=True,
    )

    info("*** Tạo controller Ryu (remote port 6633)\n")
    c0 = net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6633)

    info("*** Tạo switch OVS\n")
    s1 = net.addSwitch("s1", protocols="OpenFlow13")

    info("*** Tạo hosts IoT\n")
    h1 = net.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")  # MQTT Broker
    h2 = net.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02")  # Normal IoT
    h3 = net.addHost("h3", ip="10.0.0.3/24", mac="00:00:00:00:00:03")  # Normal IoT
    h4 = net.addHost("h4", ip="10.0.0.4/24", mac="00:00:00:00:00:04")  # Attacker / Compromised
    h5 = net.addHost("h5", ip="10.0.0.5/24", mac="00:00:00:00:00:05")  # Normal IoT

    info("*** Kết nối hosts vào switch\n")
    # Bandwidth 100Mbps, delay 2ms để mimick mạng IoT thực tế
    net.addLink(h1, s1, bw=100, delay="2ms")
    net.addLink(h2, s1, bw=10,  delay="5ms")
    net.addLink(h3, s1, bw=10,  delay="5ms")
    net.addLink(h4, s1, bw=10,  delay="5ms")
    net.addLink(h5, s1, bw=10,  delay="5ms")

    info("*** Khởi động mạng\n")
    net.start()

    info("*** Cấu hình OVS OpenFlow 1.3\n")
    s1.cmd("ovs-vsctl set bridge s1 protocols=OpenFlow13")

    info("*** Cài đặt Mosquitto broker trên h1\n")
    h1.cmd("mosquitto -d -p 1883")
    time.sleep(1)
    info("    Mosquitto đang chạy tại 10.0.0.1:1883\n")

    info("*** Copy attack scripts vào namespace h4\n")
    scripts = [
        "attack1_mqtt_flood.py",
        "attack2_c2_malware.py",
        "attack3_bruteforce.py",
        "attack4_port_scan.py",
        "attack5_slow_drip.py",
        "normal_traffic.py",
        "evaluation.py",
    ]
    for s in scripts:
        if os.path.exists(s):
            info(f"    ✓ {s} có sẵn\n")
        else:
            info(f"    ✗ {s} chưa tồn tại — hãy copy vào cùng thư mục\n")

    info("\n" + "="*55 + "\n")
    info("   TOPOLOGY MQTT IoT SDN SẴN SÀNG\n")
    info("="*55 + "\n")
    info("Hosts:\n")
    info("  h1 10.0.0.1 — MQTT Broker (Mosquitto)\n")
    info("  h2 10.0.0.2 — IoT Sensor bình thường\n")
    info("  h3 10.0.0.3 — IoT Sensor bình thường\n")
    info("  h4 10.0.0.4 — Thiết bị bị compromise (ATTACKER)\n")
    info("  h5 10.0.0.5 — IoT Sensor bình thường\n")
    info("\n")
    info("Lệnh chạy attack từ CLI:\n")
    info("  mininet> h4 python3 attack1_mqtt_flood.py --broker 10.0.0.1 &\n")
    info("  mininet> h4 python3 attack2_c2_malware.py --mode client --broker 10.0.0.1 &\n")
    info("  mininet> h4 python3 attack3_bruteforce.py --broker 10.0.0.1 &\n")
    info("  mininet> h4 python3 attack4_port_scan.py --target 10.0.0.0/24 &\n")
    info("  mininet> h4 python3 attack5_slow_drip.py --broker 10.0.0.1 &\n")
    info("\nChạy normal traffic:\n")
    info("  mininet> h2 python3 normal_traffic.py --broker 10.0.0.1 &\n")
    info("="*55 + "\n")

    CLI(net)

    info("*** Dừng mạng\n")
    net.stop()


if __name__ == "__main__":
    build_topology()
