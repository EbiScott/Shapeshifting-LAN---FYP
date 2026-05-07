"""
This file builds on Phase 2 (analyzer_controller.py) by adding a
DetectionEngine class that analyses the accumulated traffic counters
and classifies network behaviour into three threat states:

    NORMAL     — traffic looks legitimate, no action required
    SUSPICIOUS — anomalous pattern detected, monitoring intensified
    MALICIOUS  — confirmed attack behaviour, mutation engine triggered (Phase 4)

Detection methods used:
    i.   Shannon entropy on destination port distribution  → detects port scans
    ii.  SYN/ACK ratio threshold                          → detects SYN floods
    iii. Flow velocity (new flows per time window)         → detects reconnaissance
    iv.  Repeated connection counter per source IP         → detects brute force

Run with:
    ryu-manager shapeshifting_controller.py

Then in a separate terminal:
    sudo python3 topology.pys
    
    Or via mn command:
    sudo mn --custom topology.py --topo shapeshifting \
            --controller=remote --switch ovs,protocols=OpenFlow13_
"""

#!/usr/bin/env python3

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (CONFIG_DISPATCHER, MAIN_DISPATCHER,
                                     set_ev_cls)
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp
from ryu.lib import hub
import collections
import time
import math


# ======================================================================
#  DETECTION THRESHOLDS
#  These values define the boundary between normal and suspicious/
#  malicious behaviour. They can be tuned based on evaluation results.
# ======================================================================

ENTROPY_SUSPICIOUS  = 3.0   # bits — port entropy above this = suspicious
ENTROPY_MALICIOUS   = 4.5   # bits — port entropy above this = malicious (port scan)

SYN_RATIO_SUSPICIOUS = 3.0  # SYN packets 3x more than ACK = suspicious
SYN_RATIO_MALICIOUS  = 7.0  # SYN packets 7x more than ACK = SYN flood

FLOW_RATE_SUSPICIOUS = 10   # more than 10 new flows in one window = suspicious
FLOW_RATE_MALICIOUS  = 20   # more than 20 new flows in one window = malicious

BRUTE_FORCE_SUSPICIOUS = 10  # same src IP hitting same dst port > 10 times
BRUTE_FORCE_MALICIOUS  = 25  # same src IP hitting same dst port > 25 times

DETECTION_INTERVAL  = 10    # seconds between each detection cycle
POLL_INTERVAL       = 10    # seconds between flow stat requests


# ======================================================================
#  THREAT STATE CONSTANTS
# ======================================================================

NORMAL     = "NORMAL"
SUSPICIOUS = "SUSPICIOUS"
MALICIOUS  = "MALICIOUS"


# ======================================================================
#  DETECTION ENGINE
#  This is a standalone class — it only reads traffic data and produces
#  a threat classification. It does not touch the network directly.
#  Phase 4 (the Mutation Engine) will act on its output.
# ======================================================================

class DetectionEngine:
    """
    Analyses accumulated traffic features and classifies the current
    network state as NORMAL, SUSPICIOUS, or MALICIOUS.

    This class is intentionally separated from the Ryu controller so
    that the detection logic and the network control logic remain
    independent, matching the two-subsystem architecture described in
    Chapter 3.
    """

    def __init__(self, logger):
        self.logger = logger

    # ------------------------------------------------------------------
    #  MAIN ANALYSIS METHOD
    #  Called every DETECTION_INTERVAL seconds by the controller.
    #  Returns a dict with one result per detection method.
    # ------------------------------------------------------------------
    def analyse(self, dst_port_counts, tcp_flag_counts,
                src_ip_counts, flow_count_window,
                connection_tracker):
        """
        Runs all four detection methods and returns a combined result.

        Parameters
        ----------
        dst_port_counts    : Counter  — destination ports seen across all packets
        tcp_flag_counts    : Counter  — TCP flag combinations seen
        src_ip_counts      : Counter  — source IPs seen
        flow_count_window  : int      — number of new flows in the last window
        connection_tracker : dict     — {(src_ip, dst_port): count}

        Returns
        -------
        dict with keys: entropy_state, syn_state, flow_state,
                        brute_state, overall_state, details
        """

        results = {}

        # --- Method i: Shannon entropy on destination ports ---
        results['entropy_state'], results['entropy_value'] = \
            self._check_port_entropy(dst_port_counts)

        # --- Method ii: SYN/ACK ratio ---
        results['syn_state'], results['syn_ratio'] = \
            self._check_syn_ratio(tcp_flag_counts)

        # --- Method iii: Flow velocity ---
        results['flow_state'] = \
            self._check_flow_velocity(flow_count_window)

        # --- Method iv: Brute force ---
        results['brute_state'], results['brute_detail'] = \
            self._check_brute_force(connection_tracker)

        # --- Overall state: worst case across all methods ---
        all_states = [
            results['entropy_state'],
            results['syn_state'],
            results['flow_state'],
            results['brute_state']
        ]
        if MALICIOUS in all_states:
            results['overall_state'] = MALICIOUS
        elif SUSPICIOUS in all_states:
            results['overall_state'] = SUSPICIOUS
        else:
            results['overall_state'] = NORMAL

        self._log_results(results)
        return results

    # ------------------------------------------------------------------
    #  METHOD i — SHANNON ENTROPY ON DESTINATION PORT DISTRIBUTION
    #
    #  Shannon entropy H = - Σ p(x) * log2(p(x))
    #
    #  p(x) is the proportion of packets that went to port x.
    #  Low entropy  → traffic concentrated on few ports → normal
    #  High entropy → traffic spread across many ports  → port scan
    # ------------------------------------------------------------------
    def _check_port_entropy(self, dst_port_counts):
        total = sum(dst_port_counts.values())
        if total == 0:
            return NORMAL, 0.0

        # Calculate entropy
        entropy = 0.0
        for count in dst_port_counts.values():
            p = count / total              # proportion of traffic to this port
            entropy -= p * math.log2(p)   # entropy formula

        if entropy >= ENTROPY_MALICIOUS:
            return MALICIOUS, entropy
        elif entropy >= ENTROPY_SUSPICIOUS:
            return SUSPICIOUS, entropy
        else:
            return NORMAL, entropy

    # ------------------------------------------------------------------
    #  METHOD ii — SYN/ACK RATIO
    #
    #  Counts packets with SYN flag set vs packets with ACK flag set.
    #  In normal traffic these are roughly balanced because every
    #  connection completes its handshake.
    #  In a SYN flood: many SYNs arrive, few ACKs ever follow.
    # ------------------------------------------------------------------
    def _check_syn_ratio(self, tcp_flag_counts):
        # Count all packets containing SYN flag (includes SYN-ACK)
        syn_count = sum(
            count for flags, count in tcp_flag_counts.items()
            if 'SYN' in flags
        )
        # Count all packets containing ACK flag
        ack_count = sum(
            count for flags, count in tcp_flag_counts.items()
            if 'ACK' in flags
        )

        if ack_count == 0:
            # No ACKs at all — suspicious if there are SYNs
            ratio = float(syn_count) if syn_count > 0 else 0.0
        else:
            ratio = syn_count / ack_count

        if ratio >= SYN_RATIO_MALICIOUS:
            return MALICIOUS, ratio
        elif ratio >= SYN_RATIO_SUSPICIOUS:
            return SUSPICIOUS, ratio
        else:
            return NORMAL, ratio

    # ------------------------------------------------------------------
    #  METHOD iii — FLOW VELOCITY
    #
    #  Counts how many new flows appeared in the last detection window.
    #  Normal traffic: new flows appear gradually.
    #  Reconnaissance: many new flows appear very quickly as the attacker
    #  probes different hosts and services.
    # ------------------------------------------------------------------
    def _check_flow_velocity(self, flow_count_window):
        if flow_count_window >= FLOW_RATE_MALICIOUS:
            return MALICIOUS
        elif flow_count_window >= FLOW_RATE_SUSPICIOUS:
            return SUSPICIOUS
        else:
            return NORMAL

    # ------------------------------------------------------------------
    #  METHOD iv — BRUTE FORCE DETECTION
    #
    #  Tracks how many times the same source IP has contacted the same
    #  destination port. Brute force attacks (e.g. SSH password guessing)
    #  generate a very high count for one specific (src_ip, dst_port) pair.
    # ------------------------------------------------------------------
    def _check_brute_force(self, connection_tracker):
        if not connection_tracker:
            return NORMAL, None

        # Find the most active (src_ip, dst_port) pair
        worst_pair  = max(connection_tracker, key=connection_tracker.get)
        worst_count = connection_tracker[worst_pair]

        detail = {
            'src_ip'   : worst_pair[0],
            'dst_port' : worst_pair[1],
            'count'    : worst_count
        }

        if worst_count >= BRUTE_FORCE_MALICIOUS:
            return MALICIOUS, detail
        elif worst_count >= BRUTE_FORCE_SUSPICIOUS:
            return SUSPICIOUS, detail
        else:
            return NORMAL, detail

    # ------------------------------------------------------------------
    #  LOGGING
    # ------------------------------------------------------------------
    def _log_results(self, r):
        self.logger.info("\n" + "=" * 60)
        self.logger.info("  DETECTION CYCLE RESULTS")
        self.logger.info("=" * 60)
        self.logger.info(
            "  [i]   Port entropy    : %.3f bits  → %s",
            r['entropy_value'], r['entropy_state']
        )
        self.logger.info(
            "  [ii]  SYN/ACK ratio   : %.2f        → %s",
            r['syn_ratio'], r['syn_state']
        )
        self.logger.info(
            "  [iii] Flow velocity   :             → %s",
            r['flow_state']
        )
        self.logger.info(
            "  [iv]  Brute force     : %s          → %s",
            r['brute_detail'], r['brute_state']
        )
        self.logger.info("  %-30s %s", "OVERALL STATE:", r['overall_state'])
        self.logger.info("=" * 60 + "\n")


# ======================================================================
#  RYU CONTROLLER
#  Handles all SDN communication. Feeds data into DetectionEngine
#  and will pass results to MutationEngine in Phase 4.
# ======================================================================

class ShapeShiftingController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ShapeShiftingController, self).__init__(*args, **kwargs)

        # ---- Network state ----
        self.mac_to_port = {}    # MAC learning table {dpid: {mac: port}}
        self.datapaths   = {}    # connected switches  {dpid: datapath}

        # ---- Traffic feature counters (fed by packet_in_handler) ----
        self.dst_port_counts  = collections.Counter()
        self.src_ip_counts    = collections.Counter()
        self.tcp_flag_counts  = collections.Counter()

        # ---- Brute force tracker: {(src_ip, dst_port): count} ----
        self.connection_tracker = collections.Counter()

        # ---- Flow velocity tracking ----
        self.flow_count_window   = 0   # new flows seen in current window
        self.last_window_reset   = time.time()

        # ---- Detection engine (separate class, reads counters only) ----
        self.detection_engine = DetectionEngine(self.logger)

        # ---- Background threads ----
        self.monitor_thread   = hub.spawn(self._monitor_loop)
        self.detection_thread = hub.spawn(self._detection_loop)

    # ------------------------------------------------------------------
    #  SWITCH HANDSHAKE
    # ------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser

        self.datapaths[datapath.id] = datapath
        self.logger.info("[SETUP] Switch %s connected", datapath.id)

        # Table-miss: send unknown packets to controller
        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, priority=0, match=match, actions=actions)

    # ------------------------------------------------------------------
    #  PACKET-IN HANDLER
    #  Performs MAC learning, switching, AND feature extraction.
    # ------------------------------------------------------------------
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

        # MAC learning
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port
        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions  = [parser.OFPActionOutput(out_port)]

        # Install flow rule and count it toward flow velocity
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self._add_flow(datapath, priority=1, match=match, actions=actions)
            self.flow_count_window += 1   # new flow installed

        # Forward packet
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        )
        datapath.send_msg(out)

        # Feature extraction (IP layer and above only)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt is None:
            return

        src_ip = ip_pkt.src
        self.src_ip_counts[src_ip] += 1

        tcp_pkt = pkt.get_protocol(tcp.tcp)
        if tcp_pkt:
            flags    = tcp_pkt.bits
            flag_str = self._decode_tcp_flags(flags)
            self.dst_port_counts[tcp_pkt.dst_port] += 1
            self.tcp_flag_counts[flag_str]         += 1
            # Track (src_ip, dst_port) pairs for brute force detection
            self.connection_tracker[(src_ip, tcp_pkt.dst_port)] += 1

        udp_pkt = pkt.get_protocol(udp.udp)
        if udp_pkt:
            self.dst_port_counts[udp_pkt.dst_port] += 1

    # ------------------------------------------------------------------
    #  FLOW STATS REPLY
    # ------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        flows = ev.msg.body
        active = [f for f in flows if f.priority > 0]
        self.logger.info("[STATS] Switch %s — %d active flows",
                         ev.msg.datapath.id, len(active))
        for stat in active:
            m = stat.match
            self.logger.info(
                "  in_port=%-4s src=%-20s dst=%-20s "
                "packets=%-6d bytes=%-8d duration=%ds",
                m.get('in_port', '?'), m.get('eth_src', '?'),
                m.get('eth_dst', '?'), stat.packet_count,
                stat.byte_count, stat.duration_sec
            )

    # ------------------------------------------------------------------
    #  BACKGROUND LOOPS
    # ------------------------------------------------------------------
    def _monitor_loop(self):
        """Polls switch for flow stats every POLL_INTERVAL seconds."""
        while True:
            hub.sleep(POLL_INTERVAL)
            for dp in list(self.datapaths.values()):
                parser  = dp.ofproto_parser
                request = parser.OFPFlowStatsRequest(dp)
                dp.send_msg(request)

    def _detection_loop(self):
        """Runs the detection engine every DETECTION_INTERVAL seconds."""
        while True:
            hub.sleep(DETECTION_INTERVAL)

            # Run detection
            result = self.detection_engine.analyse(
                dst_port_counts    = self.dst_port_counts,
                tcp_flag_counts    = self.tcp_flag_counts,
                src_ip_counts      = self.src_ip_counts,
                flow_count_window  = self.flow_count_window,
                connection_tracker = self.connection_tracker
            )

            # Reset the flow velocity window counter after each cycle
            self.flow_count_window = 0

            # ---- Phase 4 hook ----
            # The overall_state is the output of the detection layer.
            # In Phase 4, this is where the MutationEngine will be called:
            #
            #   if result['overall_state'] == MALICIOUS:
            #       self.mutation_engine.respond(result)
            #
            # For now we just log it clearly.
            state = result['overall_state']
            if state == MALICIOUS:
                self.logger.warning(
                    "[DETECTION] *** MALICIOUS ACTIVITY DETECTED ***"
                    " — Mutation engine will be triggered in Phase 4"
                )
            elif state == SUSPICIOUS:
                self.logger.warning(
                    "[DETECTION] Suspicious activity detected — monitoring"
                )
            else:
                self.logger.info("[DETECTION] Traffic state: NORMAL")

    # ------------------------------------------------------------------
    #  HELPERS
    # ------------------------------------------------------------------
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
        names = [(0x01, 'FIN'), (0x02, 'SYN'), (0x04, 'RST'),
                 (0x08, 'PSH'), (0x10, 'ACK'), (0x20, 'URG')]
        return '|'.join(name for bit, name in names if bits & bit) or 'NONE'
