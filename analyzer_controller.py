#!/usr/bin/env python3

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls)
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp
from ryu.lib import hub
import collections
import time

POLL_INTERVAL = 10   # seconds between flow-stat requests


class NetworkAnalyzer(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(NetworkAnalyzer, self).__init__(*args, **kwargs)
        self.mac_to_port  = {}       # MAC learning table  {dpid: {mac: port}}
        self.datapaths    = {}       # connected switches   {dpid: datapath}

        # ---- Feature tracking (used by Phase 3 detection) ----
        # dst_port_counts  : how many packets hit each destination port
        # src_ip_counts    : how many packets came from each source IP
        # tcp_flag_counts  : count of each TCP flag combination seen
        self.dst_port_counts = collections.Counter()
        self.src_ip_counts   = collections.Counter()
        self.tcp_flag_counts = collections.Counter()

        # Spawn background thread for flow-stat polling
        self.monitor_thread = hub.spawn(self._monitor_loop)

    # ------------------------------------------------------------------ #
    #  SWITCH HANDSHAKE                                                    #
    # ------------------------------------------------------------------ #
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser

        self.datapaths[datapath.id] = datapath
        self.logger.info("[SETUP] Switch %s connected", datapath.id)

        # Table-miss rule: send all unknown packets to controller
        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, priority=0, match=match, actions=actions)

    # ------------------------------------------------------------------ #
    #  PACKET-IN HANDLER — fine-grained per-packet feature extraction     #
    # ------------------------------------------------------------------ #
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg      = ev.msg
        datapath = msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        in_port  = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        dst  = eth.dst
        src  = eth.src
        dpid = datapath.id

        # ---------- MAC learning ----------
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port
        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)

        actions = [parser.OFPActionOutput(out_port)]

        # Install flow so subsequent packets bypass the controller
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self._add_flow(datapath, priority=1, match=match, actions=actions)

        # Forward the current packet
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None)
        datapath.send_msg(out)

        # ---------- Feature extraction ----------
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt is None:
            return   # ignore non-IP traffic (ARP etc.)

        src_ip   = ip_pkt.src
        dst_ip   = ip_pkt.dst
        proto    = ip_pkt.proto

        self.src_ip_counts[src_ip] += 1

        print("\n--- Packet Observed ---")
        print(f"  Source IP      : {src_ip}")
        print(f"  Destination IP : {dst_ip}")
        print(f"  Protocol       : {proto}  "
              f"({'TCP' if proto == 6 else 'UDP' if proto == 17 else 'ICMP' if proto == 1 else 'other'})")

        tcp_pkt = pkt.get_protocol(tcp.tcp)
        if tcp_pkt:
            flags = tcp_pkt.bits   # bitmask: SYN=0x02 ACK=0x10 FIN=0x01 RST=0x04
            flag_str = self._decode_tcp_flags(flags)
            self.dst_port_counts[tcp_pkt.dst_port] += 1
            self.tcp_flag_counts[flag_str]         += 1
            print(f"  TCP src_port   : {tcp_pkt.src_port}")
            print(f"  TCP dst_port   : {tcp_pkt.dst_port}")
            print(f"  TCP flags      : {flag_str}  (raw={flags:#04x})")

        udp_pkt = pkt.get_protocol(udp.udp)
        if udp_pkt:
            self.dst_port_counts[udp_pkt.dst_port] += 1
            print(f"  UDP src_port   : {udp_pkt.src_port}")
            print(f"  UDP dst_port   : {udp_pkt.dst_port}")

        # Print running summaries every 20 packets
        total = sum(self.src_ip_counts.values())
        if total % 20 == 0 and total > 0:
            self._print_summary()

    # ------------------------------------------------------------------ #
    #  FLOW STATS REPLY — aggregate per-flow counters from the switch     #
    # ------------------------------------------------------------------ #
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        flows = ev.msg.body
        self.logger.info("\n========== FLOW STATS  Switch %s  [%s] ==========",
                         ev.msg.datapath.id,
                         time.strftime("%H:%M:%S"))

        active_flows = [f for f in flows if f.priority > 0]
        if not active_flows:
            self.logger.info("  (no active flows yet)")
        else:
            for stat in active_flows:
                m = stat.match
                self.logger.info(
                    "  in_port=%-4s  src=%-20s  dst=%-20s  "
                    "packets=%-6d  bytes=%-8d  duration=%ds",
                    m.get('in_port', '?'),
                    m.get('eth_src',  '?'),
                    m.get('eth_dst',  '?'),
                    stat.packet_count,
                    stat.byte_count,
                    stat.duration_sec
                )

        self.logger.info("  --- Accumulated packet-level counters ---")
        self.logger.info("  Top destination ports : %s",
                         self.dst_port_counts.most_common(5))
        self.logger.info("  Top source IPs        : %s",
                         self.src_ip_counts.most_common(5))
        self.logger.info("  TCP flag distribution : %s",
                         dict(self.tcp_flag_counts))
        self.logger.info("=" * 56 + "\n")

    # ------------------------------------------------------------------ #
    #  BACKGROUND MONITOR LOOP                                            #
    # ------------------------------------------------------------------ #
    def _monitor_loop(self):
        """Periodically request flow statistics from every connected switch."""
        while True:
            hub.sleep(POLL_INTERVAL)
            for dp in list(self.datapaths.values()):
                parser  = dp.ofproto_parser
                request = parser.OFPFlowStatsRequest(dp)
                dp.send_msg(request)
                self.logger.info("[MONITOR] Polled switch %s", dp.id)

    # ------------------------------------------------------------------ #
    #  HELPERS                                                             #
    # ------------------------------------------------------------------ #
    def _add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        inst    = [parser.OFPInstructionActions(
                       ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @staticmethod
    def _decode_tcp_flags(bits):
        """Return a human-readable string of set TCP flags."""
        names = [(0x01, 'FIN'), (0x02, 'SYN'), (0x04, 'RST'),
                 (0x08, 'PSH'), (0x10, 'ACK'), (0x20, 'URG')]
        return '|'.join(name for bit, name in names if bits & bit) or 'NONE'

    def _print_summary(self):
        print("\n===== Running Feature Summary =====")
        print("  Top destination ports :", self.dst_port_counts.most_common(5))
        print("  Top source IPs        :", self.src_ip_counts.most_common(5))
        print("  TCP flags seen        :", dict(self.tcp_flag_counts))
        print("===================================\n")

