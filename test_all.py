from scapy.all import *
import time
import random
import sys

# Pass target IP as argument, default to 10.0.0.2
target_ip = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.2"

print("=" * 50)
print("SHAPESHIFTING LAN DEFENCE - TEST SUITE")
print(f"Target: {target_ip}")
print("=" * 50)

# ── NORMAL TRAFFIC ──────────────────────────────────
def normal_traffic():
    print("\n[NORMAL] Sending legitimate traffic...")
    normal_ports = [80, 443, 22, 53]
    for i in range(10):
        port = random.choice(normal_ports)
        pkt = IP(dst=target_ip)/TCP(dport=port, flags="S")
        send(pkt, verbose=0)
        time.sleep(0.5)
    for i in range(8):
        pkt = IP(dst=target_ip)/TCP(dport=80, flags="A")
        send(pkt, verbose=0)
    print("[NORMAL] Done. Controller should show no alerts.")

# ── TEST 1: PORT ENTROPY ─────────────────────────────
def test_entropy_suspicious():
    print("\n[ENTROPY - SUSPICIOUS] Scanning moderate port range...")
    for port in range(1, 20):
        pkt = IP(dst=target_ip)/TCP(dport=port, flags="S")
        send(pkt, verbose=0)
        time.sleep(0.05)
    print("[ENTROPY - SUSPICIOUS] Done.")

def test_entropy_malicious():
    print("\n[ENTROPY - MALICIOUS] Scanning wide port range...")
    for port in range(1, 100):
        pkt = IP(dst=target_ip)/TCP(dport=port, flags="S")
        send(pkt, verbose=0)
        time.sleep(0.01)
    print("[ENTROPY - MALICIOUS] Done.")

# ── TEST 2: SYN/ACK RATIO ───────────────────────────
def test_syn_ack_suspicious():
    print("\n[SYN/ACK - SUSPICIOUS] Sending moderate SYN flood...")
    for i in range(30):
        pkt = IP(dst=target_ip)/TCP(dport=80, flags="S")
        send(pkt, verbose=0)
    for i in range(5):
        pkt = IP(dst=target_ip)/TCP(dport=80, flags="A")
        send(pkt, verbose=0)
    print("[SYN/ACK - SUSPICIOUS] Done.")

def test_syn_ack_malicious():
    print("\n[SYN/ACK - MALICIOUS] Sending heavy SYN flood...")
    for i in range(100):
        pkt = IP(dst=target_ip)/TCP(dport=80, flags="S")
        send(pkt, verbose=0)
    print("[SYN/ACK - MALICIOUS] Done.")

# ── TEST 3: FLOW VELOCITY ───────────────────────────
def test_flow_velocity_suspicious():
    print("\n[FLOW VELOCITY - SUSPICIOUS] Sending moderate flow burst...")
    for i in range(20):
        port = random.randint(1024, 65535)
        pkt = IP(dst=target_ip)/TCP(dport=port, flags="S")
        send(pkt, verbose=0)
        time.sleep(0.02)
    print("[FLOW VELOCITY - SUSPICIOUS] Done.")

def test_flow_velocity_malicious():
    print("\n[FLOW VELOCITY - MALICIOUS] Sending rapid flow burst...")
    for i in range(80):
        port = random.randint(1024, 65535)
        pkt = IP(dst=target_ip)/TCP(dport=port, flags="S")
        send(pkt, verbose=0)
        time.sleep(0.005)
    print("[FLOW VELOCITY - MALICIOUS] Done.")

# ── TEST 4: CONNECTION FREQUENCY / BRUTE FORCE ──────
def test_brute_force_suspicious():
    print("\n[BRUTE FORCE - SUSPICIOUS] Sending moderate repeated connections...")
    for i in range(20):
        pkt = IP(dst=target_ip)/TCP(dport=22, flags="S")
        send(pkt, verbose=0)
        time.sleep(0.1)
    print("[BRUTE FORCE - SUSPICIOUS] Done.")

def test_brute_force_malicious():
    print("\n[BRUTE FORCE - MALICIOUS] Sending rapid repeated connections...")
    for i in range(80):
        pkt = IP(dst=target_ip)/TCP(dport=22, flags="S")
        send(pkt, verbose=0)
        time.sleep(0.01)
    print("[BRUTE FORCE - MALICIOUS] Done.")

# ── RUN ALL TESTS ────────────────────────────────────
print("\nStarting with normal traffic baseline...")
normal_traffic()
time.sleep(3)

print("\n--- ENTROPY TESTS ---")
test_entropy_suspicious()
time.sleep(3)
test_entropy_malicious()
time.sleep(3)

print("\n--- SYN/ACK RATIO TESTS ---")
test_syn_ack_suspicious()
time.sleep(3)
test_syn_ack_malicious()
time.sleep(3)

print("\n--- FLOW VELOCITY TESTS ---")
test_flow_velocity_suspicious()
time.sleep(3)
test_flow_velocity_malicious()
time.sleep(3)

print("\n--- BRUTE FORCE TESTS ---")
test_brute_force_suspicious()
time.sleep(3)
test_brute_force_malicious()
time.sleep(3)

print("\n" + "=" * 50)
print("ALL TESTS COMPLETE")
print("=" * 50)
