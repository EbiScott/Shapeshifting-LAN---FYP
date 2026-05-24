"""
Shapeshifting LAN Defence - Interactive Test Suite

Run from inside Mininet CLI:
    h1 python3 test_suite.py 10.0.0.4
    h2 python3 test_suite.py 10.0.0.4
    h3 python3 test_suite.py 10.0.0.4

The target should normally be h4 (the server at 10.0.0.4).
You can also target any other host IP.
"""

from scapy.all import *
import time
import random
import sys

# ── TARGET ───────────────────────────────────────────
target_ip = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.4"

# ── MENU ─────────────────────────────────────────────
MENU = """
===========================================================
       SHAPESHIFTING LAN -- INTERACTIVE TEST SUITE
       Target: {target}
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

# ── TEST FUNCTIONS ────────────────────────────────────

def normal_traffic():
    """
    Sends a realistic mix of HTTP, HTTPS, SSH, and DNS packets
    with balanced SYN and ACK flags -- represents a healthy baseline.
    Expected controller response: NORMAL
    """
    print("\n[NORMAL] Sending legitimate baseline traffic...")
    normal_ports = [80, 443, 22, 53]

    for i in range(10):
        port = random.choice(normal_ports)
        send(IP(dst=target_ip)/TCP(dport=port, flags="S"), verbose=0)
        time.sleep(0.3)

    for i in range(8):
        send(IP(dst=target_ip)/TCP(dport=80, flags="A"), verbose=0)
        time.sleep(0.1)

    print("[NORMAL] Done -- wait for next detection cycle to confirm NORMAL state.")


def test_entropy_suspicious():
    """
    Scans 20 sequential ports with SYN packets.
    Spreads traffic across enough ports to raise entropy above
    the SUSPICIOUS threshold (3.0 bits) but below MALICIOUS (4.5 bits).
    Expected controller response: SUSPICIOUS -- port_entropy
    """
    print("\n[ENTROPY - SUSPICIOUS] Scanning ports 1-20 on {}...".format(target_ip))
    for port in range(1, 21):
        send(IP(dst=target_ip)/TCP(dport=port, flags="S"), verbose=0)
        time.sleep(0.05)
    print("[ENTROPY - SUSPICIOUS] Done -- watch controller for SUSPICIOUS alert.")


def test_entropy_malicious():
    """
    Scans 100 sequential ports with SYN packets.
    Wide port distribution pushes entropy well above the MALICIOUS
    threshold (4.5 bits), simulating a full port scan.
    Expected controller response: MALICIOUS -- port_entropy -> port hop mutation
    """
    print("\n[ENTROPY - MALICIOUS] Scanning ports 1-100 on {}...".format(target_ip))
    for port in range(1, 101):
        send(IP(dst=target_ip)/TCP(dport=port, flags="S"), verbose=0)
        time.sleep(0.01)
    print("[ENTROPY - MALICIOUS] Done -- watch controller for MALICIOUS alert and port hop.")


def test_syn_suspicious():
    """
    Sends 30 SYN packets and only 5 ACK packets to port 80.
    SYN/ACK ratio = 6.0, above SUSPICIOUS threshold (3.0)
    but below MALICIOUS (7.0).
    Expected controller response: SUSPICIOUS -- syn_ratio
    """
    print("\n[SYN FLOOD - SUSPICIOUS] 30 SYN + 5 ACK to port 80 on {}...".format(target_ip))
    for i in range(30):
        send(IP(dst=target_ip)/TCP(dport=80, flags="S"), verbose=0)
    for i in range(5):
        send(IP(dst=target_ip)/TCP(dport=80, flags="A"), verbose=0)
    print("[SYN FLOOD - SUSPICIOUS] Done -- watch controller for SUSPICIOUS alert.")


def test_syn_malicious():
    """
    Sends 100 SYN packets with zero ACK packets to port 80.
    SYN/ACK ratio = infinity (no ACKs), far above MALICIOUS threshold (7.0).
    Simulates a full SYN flood denial-of-service attack.
    Expected controller response: MALICIOUS -- syn_ratio -> source block mutation
    """
    print("\n[SYN FLOOD - MALICIOUS] 100 SYN, 0 ACK to port 80 on {}...".format(target_ip))
    for i in range(100):
        send(IP(dst=target_ip)/TCP(dport=80, flags="S"), verbose=0)
    print("[SYN FLOOD - MALICIOUS] Done -- watch controller for MALICIOUS alert and source block.")


def test_flow_suspicious():
    """
    Opens 20 connections to random high ports rapidly.
    Generates enough new flows to cross the SUSPICIOUS flow velocity
    threshold (20 flows/window).
    Expected controller response: SUSPICIOUS -- flow_velocity
    """
    print("\n[FLOW VELOCITY - SUSPICIOUS] 20 connections to random ports on {}...".format(target_ip))
    for i in range(20):
        port = random.randint(1024, 65535)
        send(IP(dst=target_ip)/TCP(dport=port, flags="S"), verbose=0)
        time.sleep(0.02)
    print("[FLOW VELOCITY - SUSPICIOUS] Done -- watch controller for SUSPICIOUS alert.")


def test_flow_malicious():
    """
    Opens 80 connections to random high ports in rapid succession.
    Simulates network-wide reconnaissance -- attacker mapping all
    reachable services. Crosses MALICIOUS threshold (40 flows/window).
    Expected controller response: MALICIOUS -- flow_velocity -> source block mutation
    """
    print("\n[FLOW VELOCITY - MALICIOUS] 80 rapid connections to random ports on {}...".format(target_ip))
    for i in range(80):
        port = random.randint(1024, 65535)
        send(IP(dst=target_ip)/TCP(dport=port, flags="S"), verbose=0)
        time.sleep(0.005)
    print("[FLOW VELOCITY - MALICIOUS] Done -- watch controller for MALICIOUS alert.")


def test_brute_suspicious():
    """
    Sends 20 repeated SYN packets to port 22 (SSH) from same source.
    Simulates a slow brute force attempt -- enough to cross the
    SUSPICIOUS threshold (10 repeated connections) but not MALICIOUS (25).
    Expected controller response: SUSPICIOUS -- brute_force
    """
    print("\n[BRUTE FORCE - SUSPICIOUS] 20 repeated SYN to port 22 on {}...".format(target_ip))
    for i in range(20):
        send(IP(dst=target_ip)/TCP(dport=22, flags="S"), verbose=0)
        time.sleep(0.1)
    print("[BRUTE FORCE - SUSPICIOUS] Done -- watch controller for SUSPICIOUS alert.")


def test_brute_malicious():
    """
    Sends 80 rapid SYN packets to port 22 (SSH) from same source.
    Simulates an aggressive SSH brute force attack -- crosses the
    MALICIOUS threshold (25 repeated connections).
    Expected controller response: MALICIOUS -- brute_force -> source block mutation
    """
    print("\n[BRUTE FORCE - MALICIOUS] 80 rapid SYN to port 22 on {}...".format(target_ip))
    for i in range(80):
        send(IP(dst=target_ip)/TCP(dport=22, flags="S"), verbose=0)
        time.sleep(0.01)
    print("[BRUTE FORCE - MALICIOUS] Done -- watch controller for MALICIOUS alert and source block.")


# ── DISPATCH TABLE ────────────────────────────────────

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

# ── MAIN LOOP ─────────────────────────────────────────

if __name__ == '__main__':
    print(MENU.format(target=target_ip))
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
            TESTS[choice]()
            print("\n>>> Waiting for detection cycle (up to 10s)...")
            print(">>> Watch the controller terminal for results.")
            print(">>> Press Enter when ready for next test.\n")
            input()
        else:
            print("Invalid choice. Enter 0-8 or q.\n")
