from scapy.all import *

target_ip = "10.0.0.2"  # h2

# SYN flood - triggers SYN/ACK ratio threshold
def syn_flood():
    for i in range(100):
        pkt = IP(dst=target_ip)/TCP(dport=80, flags="S")
        send(pkt, verbose=0)
    print("SYN flood done")

# Port scan - triggers flow velocity
def port_scan():
    for port in range(1, 100):
        pkt = IP(dst=target_ip)/TCP(dport=port, flags="S")
        send(pkt, verbose=0)
    print("Port scan done")

# Connection frequency - rapid repeated connections
def conn_frequency():
    for i in range(50):
        pkt = IP(dst=target_ip)/TCP(dport=22, flags="S")
        send(pkt, verbose=0)
    print("Connection frequency test done")

syn_flood()
port_scan()
conn_frequency()
