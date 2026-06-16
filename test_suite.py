"""
Shapeshifting LAN Defence - Interactive Test Suite
With automatic test marking via shared marker file.

The suite writes a marker to ~/FYP/pending_marker.txt before each test.
The controller reads this file at the start of each detection cycle
and attaches the label to the cycle in detection_history.json.

Run from inside Mininet CLI:
    h1 python3 test_suite.py 10.0.0.4
    h2 python3 test_suite.py 10.0.0.4
    h3 python3 test_suite.py 10.0.0.4
"""

from scapy.all import *
import time
import random
import sys
import os

target_ip   = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.4"
source_host = sys.argv[2] if len(sys.argv) > 2 else "h1"

MARKER_FILE = "/home/mininet/FYP/pending_marker.txt"

MENU = """
===========================================================
       SHAPESHIFTING LAN -- INTERACTIVE TEST SUITE
       Source: {source}   Target: {target}
===========================================================
  NORMAL TRAFFIC
    0  --  Send normal baseline traffic

  PORT ENTROPY (port scan detection)
    1  --  Entropy  SUSPICIOUS  (scan 20 ports)
    2  --  Entropy  MALICIOUS   (scan 100 ports)

  SYN/ACK RATIO (SYN flood detection)
    3  --  SYN flood  SUSPICIOUS  (30 SYN, 5 ACK)
    4  --  SYN flood  MALICIOUS   (100 SYN, 0 ACK)

  FLOW VELOCITY (reconnaissance detection)
    5  --  Flow burst  SUSPICIOUS  (20 flows)
    6  --  Flow burst  MALICIOUS   (80 flows)

  BRUTE FORCE (repeated connection detection)
    7  --  Brute force  SUSPICIOUS  (20 attempts)
    8  --  Brute force  MALICIOUS   (80 attempts)

    q  --  Quit
===========================================================
"""

LABELS = {
    '0': 'baseline',
    '1': 'entropy_sus',
    '2': 'entropy_mal',
    '3': 'syn_sus',
    '4': 'syn_mal',
    '5': 'flow_sus',
    '6': 'flow_mal',
    '7': 'brute_sus',
    '8': 'brute_mal',
}


def write_marker(test_num):
    """Write marker file so controller stamps the next detection cycle."""
    label = f"{source_host}_h4_{LABELS.get(test_num, test_num)}"
    try:
        with open(MARKER_FILE, 'w') as f:
            f.write(label)
        print(f"[MARKER] Test labelled: {label}")
    except Exception as e:
        print(f"[MARKER] Could not write marker: {e}")


def normal_traffic():
    print("\n[NORMAL] Sending legitimate baseline traffic...")
    normal_ports = [80, 443, 22, 53]
    for i in range(10):
        port = random.choice(normal_ports)
        send(IP(dst=target_ip)/TCP(dport=port, flags="S"), verbose=0)
        time.sleep(0.3)
    for i in range(8):
        send(IP(dst=target_ip)/TCP(dport=80, flags="A"), verbose=0)
    print("[NORMAL] Done.")


def test_entropy_suspicious():
    print(f"\n[ENTROPY - SUSPICIOUS] Scanning ports 1-20 on {target_ip}...")
    for port in range(1, 21):
        send(IP(dst=target_ip)/TCP(dport=port, flags="S"), verbose=0)
        time.sleep(0.05)
    print("[ENTROPY - SUSPICIOUS] Done.")


def test_entropy_malicious():
    print(f"\n[ENTROPY - MALICIOUS] Scanning ports 1-100 on {target_ip}...")
    for port in range(1, 101):
        send(IP(dst=target_ip)/TCP(dport=port, flags="S"), verbose=0)
        time.sleep(0.01)
    print("[ENTROPY - MALICIOUS] Done.")


def test_syn_suspicious():
    print(f"\n[SYN FLOOD - SUSPICIOUS] 30 SYN + 5 ACK to port 80 on {target_ip}...")
    for i in range(30):
        send(IP(dst=target_ip)/TCP(dport=80, flags="S"), verbose=0)
    for i in range(5):
        send(IP(dst=target_ip)/TCP(dport=80, flags="A"), verbose=0)
    print("[SYN FLOOD - SUSPICIOUS] Done.")


def test_syn_malicious():
    print(f"\n[SYN FLOOD - MALICIOUS] 100 SYN, 0 ACK to port 80 on {target_ip}...")
    for i in range(100):
        send(IP(dst=target_ip)/TCP(dport=80, flags="S"), verbose=0)
    print("[SYN FLOOD - MALICIOUS] Done.")


def test_flow_suspicious():
    print(f"\n[FLOW VELOCITY - SUSPICIOUS] 20 connections to random ports on {target_ip}...")
    for i in range(20):
        port = random.randint(1024, 65535)
        send(IP(dst=target_ip)/TCP(dport=port, flags="S"), verbose=0)
        time.sleep(0.02)
    print("[FLOW VELOCITY - SUSPICIOUS] Done.")


def test_flow_malicious():
    print(f"\n[FLOW VELOCITY - MALICIOUS] 80 rapid connections to random ports on {target_ip}...")
    for i in range(80):
        port = random.randint(1024, 65535)
        send(IP(dst=target_ip)/TCP(dport=port, flags="S"), verbose=0)
        time.sleep(0.005)
    print("[FLOW VELOCITY - MALICIOUS] Done.")


def test_brute_suspicious():
    print(f"\n[BRUTE FORCE - SUSPICIOUS] 20 repeated SYN to port 22 on {target_ip}...")
    for i in range(20):
        send(IP(dst=target_ip)/TCP(dport=22, flags="S"), verbose=0)
        time.sleep(0.1)
    print("[BRUTE FORCE - SUSPICIOUS] Done.")


def test_brute_malicious():
    print(f"\n[BRUTE FORCE - MALICIOUS] 80 rapid SYN to port 22 on {target_ip}...")
    for i in range(80):
        send(IP(dst=target_ip)/TCP(dport=22, flags="S"), verbose=0)
        time.sleep(0.01)
    print("[BRUTE FORCE - MALICIOUS] Done.")


TESTS = {
    '0': normal_traffic,
    '1': test_entropy_suspicious,
    '2': test_entropy_malicious,
    '3': test_syn_suspicious,
    '4': test_syn_malicious,
    '5': test_flow_suspicious,
    '6': test_flow_malicious,
    '7': test_brute_suspicious,
    '8': test_brute_malicious,
}

if __name__ == '__main__':
    print(MENU.format(source=source_host, target=target_ip))
    print("NOTE: After each test, wait up to 10 seconds for the")
    print("      detection cycle to run and show results.\n")

    while True:
        try:
            choice = input("Select test [0-8 or q]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if choice == 'q':
            print("Exiting test suite.")
            break
        elif choice in TESTS:
            write_marker(choice)
            TESTS[choice]()
            print("\n>>> Waiting for detection cycle (up to 10s)...")
            print(">>> Watch the controller terminal for results.")
            print(">>> Press Enter when ready for next test.\n")
            input()
        else:
            print("Invalid choice. Enter 0-8 or q.\n")
