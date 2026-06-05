"""
Shapeshifting LAN — Custom Mininet Topology

Topology:
    h1  10.0.0.1  (client 1) -+
    h2  10.0.0.2  (client 2) -+-- s1 --- Ryu Controller
    h3  10.0.0.3  (client 3) -+
    h4  10.0.0.4  (server)   -+

Run with:
    sudo python3 topology.py
"""

from mininet.topo import Topo
from mininet.net  import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli  import CLI
from mininet.log  import setLogLevel
import subprocess
import time


class ShapeShiftingTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1')
        h1 = self.addHost('h1', ip='10.0.0.1/24')
        h2 = self.addHost('h2', ip='10.0.0.2/24')
        h3 = self.addHost('h3', ip='10.0.0.3/24')
        h4 = self.addHost('h4', ip='10.0.0.4/24')
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)
        self.addLink(h4, s1)


topos = {'shapeshifting': ShapeShiftingTopo}


if __name__ == '__main__':
    setLogLevel('info')

    topo = ShapeShiftingTopo()
    net  = Mininet(
        topo       = topo,
        controller = RemoteController('c0', ip='127.0.0.1', port=6633),
        switch     = OVSSwitch
    )

    net.start()

    # Set switch to OpenFlow 1.3
    subprocess.call(['sudo', 'ovs-vsctl', 'set', 'bridge', 's1',
                     'protocols=OpenFlow13'])

    # Give the controller 2 seconds to install the table-miss rule.
    # If it fails to do so, install it manually as a fallback.
    time.sleep(2)
    result = subprocess.check_output(
        ['sudo', 'ovs-ofctl', 'dump-flows', 's1', '-O', 'OpenFlow13']
    ).decode()

    if 'actions=CONTROLLER' not in result:
        print("[TOPOLOGY] Controller did not install table-miss rule -- adding manually")
        subprocess.call([
            'sudo', 'ovs-ofctl', 'add-flow', 's1',
            'priority=0,actions=CONTROLLER:65535',
            '-O', 'OpenFlow13'
        ])
    else:
        print("[TOPOLOGY] Table-miss rule confirmed installed by controller")

    # Start HTTP server on h4
    h4 = net.get('h4')
    h4.cmd('python3 -m http.server 80 &')

    print("\n" + "=" * 50)
    print("  SHAPESHIFTING LAN -- NETWORK READY")
    print("=" * 50)
    print("  Clients:")
    print("    h1  --  10.0.0.1")
    print("    h2  --  10.0.0.2")
    print("    h3  --  10.0.0.3")
    print("  Server:")
    print("    h4  --  10.0.0.4  (HTTP on port 80)")
    print("  Switch:  s1  (OpenFlow 1.3)")
    print("  Controller: Ryu (remote, port 6633)")
    print("=" * 50)
    print("  Verify with:")
    print("    pingall")
    print("    h1 curl 10.0.0.4")
    print("=" * 50 + "\n")

    CLI(net)
    net.stop()
