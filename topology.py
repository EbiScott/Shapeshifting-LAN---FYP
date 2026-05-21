"""
Topology:
    h1 (client 1)  ─┐
    h2 (client 2)  ─┤
    h3 (client 3)  ─┤─── s1 ─── Ryu Controller
    h4 (server)    ─┘

h4 automatically starts an HTTP server on port 80 when the
topology launches, giving the network a real service to protect
and a realistic target for attack simulations.

Run with:
    sudo python3 topology.py

Or via mn command:
    sudo mn --custom topology.py --topo shapeshifting \
            --controller=remote --switch ovs,protocols=OpenFlow13
"""

#!/usr/bin/env python3

from mininet.topo import Topo
from mininet.net  import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli  import CLI
from mininet.log  import setLogLevel


class ShapeShiftingTopo(Topo):
    """
    Single-switch topology with three client hosts and one server host.

    Addressing:
        h1  10.0.0.1   client 1
        h2  10.0.0.2   client 2
        h3  10.0.0.3   client 3
        h4  10.0.0.4   server  (runs HTTP on port 80)
        s1  -          Open vSwitch (managed by Ryu)
    """

    def build(self):
        # Add the switch
        s1 = self.addSwitch('s1')

        # Add client hosts
        h1 = self.addHost('h1', ip='10.0.0.1/24')
        h2 = self.addHost('h2', ip='10.0.0.2/24')
        h3 = self.addHost('h3', ip='10.0.0.3/24')

        # Add server host
        h4 = self.addHost('h4', ip='10.0.0.4/24')

        # Connect all hosts to the switch
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)
        self.addLink(h4, s1)


# Required by Mininet's --custom flag
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

    # Start HTTP server on h4 automatically
    h4 = net.get('h4')
    h4.cmd('python3 -m http.server 80 &')

    print("\n" + "=" * 50)
    print("  SHAPESHIFTING LAN - NETWORK READY")
    print("=" * 50)
    print("  Clients:")
    print("    h1  -  10.0.0.1")
    print("    h2  -  10.0.0.2")
    print("    h3  -  10.0.0.3")
    print("  Server:")
    print("    h4  -  10.0.0.4  (HTTP on port 80)")
    print("  Switch:  s1  (OpenFlow 1.3)")
    print("  Controller: Ryu (remote, port 6633)")
    print("=" * 50)
    print("  Verify with:")
    print("    pingall")
    print("    h1 curl 10.0.0.4")
    print("=" * 50 + "\n")

    CLI(net)
    net.stop()
