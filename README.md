# Shapeshifting LAN Defence — FYP

A Moving Target Defence (MTD) system built on Software-Defined Networking.
The system detects network attacks in real time and mutates the network 
topology in response, using a Ryu OpenFlow 1.3 controller running over 
a Mininet virtual network.

## How It Works

The controller monitors live traffic and runs four detection metrics every 
10 seconds:

| Metric | Suspicious | Malicious | Response |
|---|---|---|---|
| Shannon Port Entropy | > 3.0 bits | > 4.5 bits | Port hop (DROP scanned port) |
| SYN/ACK Ratio | > 3.0 | > 7.0 | Source block |
| Flow Velocity | > 20 flows/window | > 40 flows/window | Source block |
| Connection Frequency | > 10 repeat conns | > 25 repeat conns | Source block |

On a **MALICIOUS** verdict the mutation engine installs timed OpenFlow 
DROP rules that automatically expire, so legitimate traffic is not 
permanently affected.

## Topology
h1 (10.0.0.1) ─┐
h2 (10.0.0.2) ─┤
s1 (OVS) ── c0 (Ryu controller)
h3 (10.0.0.3) ─┤
h4 (10.0.0.4) ─┘

## Quick Start — Pre-built VM

The fastest way to run the system. No installation required.

1. Download the VM image: **[Download OVA](#)** *(replace with your link)*
2. Import into VirtualBox: File → Import Appliance
3. Start the VM and log in: `mininet / mininet`
4. Follow the **Running the System** steps below.

## Manual Setup — Vagrant

For users who prefer to build the environment from scratch.

**Requirements:** [VirtualBox](https://www.virtualbox.org/) and 
[Vagrant](https://www.vagrantup.com/) installed on your machine.

```bash
git clone https://github.com/EbiScott/Shapeshifting-LAN---FYP.git
cd Shapeshifting-LAN---FYP
vagrant up        # takes ~10 minutes on first run
vagrant ssh       # log into the VM
cd project
```

## Running the System

You need two terminals. Use tmux:

```bash
# Start tmux
tmux

# Split into two panes
Ctrl+B then %

# Pane 1 - start the controller
ryu-manager shapeshifting_controller_V10.py

# Switch to Pane 2
Ctrl+B then right arrow

# Pane 2 - start the network
sudo python3 topology.py
```

## Testing — Interactive Test Suite

Once the controller and topology are both running, open the Mininet CLI 
and launch the interactive test suite:
mininet> h1 python3 test_suite.py 10.0.0.2

You will see a menu:
╔══════════════════════════════════════════════════════╗
║      SHAPESHIFTING LAN - INTERACTIVE TEST SUITE      ║
╠══════════════════════════════════════════════════════╣
║  0 - Normal baseline traffic                         ║
║  1 - Entropy SUSPICIOUS    2 - Entropy MALICIOUS     ║
║  3 - SYN flood SUSPICIOUS  4 - SYN flood MALICIOUS   ║
║  5 - Flow burst SUSPICIOUS 6 - Flow burst MALICIOUS  ║
║  7 - Brute force SUSPICIOUS 8 - Brute force MALICIOUS║
╚══════════════════════════════════════════════════════╝

Select a test, then watch the **controller terminal** for detection 
and mutation output. Wait up to 10 seconds between tests for the 
detection cycle to complete.

You can also run attacks from multiple hosts simultaneously:
mininet> h1 python3 test_suite.py 10.0.0.4 &
mininet> h2 python3 test_suite.py 10.0.0.4 &

## Files

| File | Description |
|---|---|
| `shapeshifting_controller_V2.py` | Main controller — detection + mutation engine |
| `topology.py` | Mininet topology — 4 hosts, 1 OVS switch |
| `test_suite.py` | Interactive attack test suite |
| `test_all.py` | Automated full test run |

## Built With

- [Ryu SDN Framework](https://github.com/faucetsdn/ryu) — OpenFlow 1.3 controller
- [Mininet](http://mininet.org/) — Virtual network emulation
- [Open vSwitch](https://www.openvswitch.org/) — Software switch
- [Scapy](https://scapy.net/) — Packet crafting for tests

## Author

Ebi Scott — Final Year Project, 2025/2026
