"""
Shapeshifting LAN Defence System
Phases 2 + 3 + 4 - Complete Implementation

Architecture (matches Chapter 3 design):
    ShapeShiftingController  - Ryu app, handles all SDN communication
    DetectionEngine          - analyses traffic features, outputs threat state
    MutationEngine           - receives threat state, applies network mutations

Detection methods:
    i.   Shannon entropy on destination port distribution  → port scan
    ii.  SYN/ACK ratio                                     → SYN flood
    iii. Flow velocity                                     → reconnaissance
    iv.  Repeated connection counter                       → brute force

Mutation responses:
    Port hopping      - redirects traffic away from scanned port (port scan)
    Flow rule rewrite - installs DROP rule for offending source IP
                        (SYN flood, brute force)

Run with:
    ryu-manager shapeshifting_controller.py

Network (start separately):
    sudo python3 topology.py
"""

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
import random


# ======================================================================
#  THRESHOLDS
#  All tunable values in one place for easy adjustment during evaluation
# ======================================================================

ENTROPY_SUSPICIOUS   = 3.0   # bits
ENTROPY_MALICIOUS    = 4.5   # bits

SYN_RATIO_SUSPICIOUS = 3.0
SYN_RATIO_MALICIOUS  = 7.0

FLOW_RATE_SUSPICIOUS = 20    # raised from 10 to account for normal startup
FLOW_RATE_MALICIOUS  = 40

BRUTE_FORCE_SUSPICIOUS = 10
BRUTE_FORCE_MALICIOUS  = 25

DETECTION_INTERVAL   = 10    # seconds between detection cycles
POLL_INTERVAL        = 10    # seconds between flow stat polls

# Mutation settings
BLOCK_RULE_TIMEOUT   = 60    # seconds before a DROP rule expires
HOP_RULE_TIMEOUT     = 30    # seconds before a port-hop rule expires
HOP_PORTS            = [8080, 8443, 9000, 9090, 7070]  # ports to hop to


# ======================================================================
#  THREAT STATE CONSTANTS
# ======================================================================

NORMAL     = "NORMAL"
SUSPICIOUS = "SUSPICIOUS"
MALICIOUS  = "MALICIOUS"


# ======================================================================
#  DETECTION ENGINE
#  Reads accumulated traffic counters and classifies threat state.
#  Does not touch the network - output only.
# ======================================================================

class DetectionEngine:

    def __init__(self, logger):
        self.logger = logger

    def analyse(self, dst_port_counts, tcp_flag_counts,
                src_ip_counts, flow_count_window, connection_tracker):
        """
        Runs all four detection methods and returns a combined result dict.
        Called every DETECTION_INTERVAL seconds by the controller.
        """
        results = {}

        results['entropy_state'],  results['entropy_value'] = \
            self._check_port_entropy(dst_port_counts)

        results['syn_state'],      results['syn_ratio'] = \
            self._check_syn_ratio(tcp_flag_counts)

        results['flow_state'] = \
            self._check_flow_velocity(flow_count_window)

        results['brute_state'],    results['brute_detail'] = \
            self._check_brute_force(connection_tracker)

        # Overall state is the worst case across all four methods
        all_states = [results['entropy_state'],  results['syn_state'],
                      results['flow_state'],      results['brute_state']]

        if MALICIOUS in all_states:
            results['overall_state'] = MALICIOUS
        elif SUSPICIOUS in all_states:
            results['overall_state'] = SUSPICIOUS
        else:
            results['overall_state'] = NORMAL

        # Identify which method triggered the worst state
        results['trigger'] = self._identify_trigger(results)

        self._log_results(results)
        return results

    # ------------------------------------------------------------------
    #  METHOD i - Shannon entropy on destination port distribution
    #  H = - sum( p(x) * log2(p(x)) )
    #  Low entropy  = traffic on few ports = normal
    #  High entropy = traffic spread across many ports = port scan
    # ------------------------------------------------------------------
    def _check_port_entropy(self, dst_port_counts):
        total = sum(dst_port_counts.values())
        if total == 0:
            return NORMAL, 0.0

        entropy = 0.0
        for count in dst_port_counts.values():
            p = count / total
            entropy -= p * math.log2(p)

        if entropy >= ENTROPY_MALICIOUS:
            return MALICIOUS, entropy
        elif entropy >= ENTROPY_SUSPICIOUS:
            return SUSPICIOUS, entropy
        else:
            return NORMAL, entropy

    # ------------------------------------------------------------------
    #  METHOD ii - SYN/ACK ratio
    #  Normal TCP completes handshake: SYN count ≈ ACK count
    #  SYN flood: many SYNs, very few ACKs
    # ------------------------------------------------------------------
    def _check_syn_ratio(self, tcp_flag_counts):
        syn_count = sum(c for f, c in tcp_flag_counts.items() if 'SYN' in f)
        ack_count = sum(c for f, c in tcp_flag_counts.items() if 'ACK' in f)

        if ack_count == 0:
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
    #  METHOD iii - Flow velocity
    #  Counts new flows installed in the last detection window.
    #  Reconnaissance generates many flows quickly.
    # ------------------------------------------------------------------
    def _check_flow_velocity(self, flow_count_window):
        if flow_count_window >= FLOW_RATE_MALICIOUS:
            return MALICIOUS
        elif flow_count_window >= FLOW_RATE_SUSPICIOUS:
            return SUSPICIOUS
        else:
            return NORMAL

    # ------------------------------------------------------------------
    #  METHOD iv - Brute force
    #  Tracks repeated connections from same source IP to same port.
    # ------------------------------------------------------------------
    def _check_brute_force(self, connection_tracker):
        if not connection_tracker:
            return NORMAL, None

        worst_pair  = max(connection_tracker, key=connection_tracker.get)
        worst_count = connection_tracker[worst_pair]
        detail = {'src_ip': worst_pair[0], 'dst_port': worst_pair[1],
                  'count': worst_count}

        if worst_count >= BRUTE_FORCE_MALICIOUS:
            return MALICIOUS, detail
        elif worst_count >= BRUTE_FORCE_SUSPICIOUS:
            return SUSPICIOUS, detail
        else:
            return NORMAL, detail

    def _identify_trigger(self, results):
        """Returns the name of the method that produced the worst state."""
        priority = {MALICIOUS: 2, SUSPICIOUS: 1, NORMAL: 0}
        methods  = {
            'port_entropy' : results['entropy_state'],
            'syn_ratio'    : results['syn_state'],
            'flow_velocity': results['flow_state'],
            'brute_force'  : results['brute_state']
        }
        return max(methods, key=lambda k: priority[methods[k]])

    def _log_results(self, r):
        self.logger.info("\n" + "=" * 60)
        self.logger.info("  DETECTION CYCLE RESULTS  [%s]",
                         time.strftime("%H:%M:%S"))
        self.logger.info("=" * 60)
        self.logger.info("  [i]   Port entropy    : %.3f bits  → %s",
                         r['entropy_value'], r['entropy_state'])
        self.logger.info("  [ii]  SYN/ACK ratio   : %.2f        → %s",
                         r['syn_ratio'], r['syn_state'])
        self.logger.info("  [iii] Flow velocity   : %-10s  → %s",
                         "", r['flow_state'])
        self.logger.info("  [iv]  Brute force     : %-10s  → %s",
                         str(r['brute_detail']), r['brute_state'])
        self.logger.info("  %-30s %s", "OVERALL STATE:", r['overall_state'])
        if r['overall_state'] != NORMAL:
            self.logger.info("  %-30s %s", "TRIGGER:", r['trigger'])
        self.logger.info("=" * 60 + "\n")


# ======================================================================
#  MUTATION ENGINE
#  Receives detection results and applies OpenFlow-based mutations.
#  Two primary mutations:
#    i.  Port hopping    - redirects traffic away from scanned port
#    ii. Flow rule rewrite - installs timed DROP rule for offending IP
# ======================================================================

class MutationEngine:

    def __init__(self, logger):
        self.logger   = logger
        self.active_mutations = []   # log of mutations applied this session

    def respond(self, detection_result, datapaths, dst_port_counts,
                src_ip_counts, connection_tracker):
        """
        Entry point called by the controller when MALICIOUS state is confirmed.
        Selects the appropriate mutation based on which method triggered.
        """
        trigger  = detection_result['trigger']
        state    = detection_result['overall_state']

        if state != MALICIOUS:
            return   # mutations only fire on confirmed malicious state

        self.logger.warning("\n*** MUTATION ENGINE ACTIVATED ***")
        self.logger.warning("    Trigger : %s", trigger)
        self.logger.warning("    Time    : %s", time.strftime("%H:%M:%S"))

        for dpid, datapath in datapaths.items():

            if trigger == 'port_entropy':
                # Port scan detected - hop the most-targeted port
                self._port_hop(datapath, dst_port_counts)

            elif trigger in ('syn_ratio', 'brute_force'):
                # SYN flood or brute force - block the top offending source IP
                self._block_source(datapath, src_ip_counts,
                                   connection_tracker, trigger)

            elif trigger == 'flow_velocity':
                # Reconnaissance - block top source IP
                self._block_source(datapath, src_ip_counts,
                                   connection_tracker, trigger)

    # ------------------------------------------------------------------
    #  MUTATION i - PORT HOPPING
    #
    #  Identifies the most-scanned destination port and installs a
    #  high-priority OpenFlow rule that DROPS packets to that port.
    #  The rule has a hard timeout (HOP_RULE_TIMEOUT seconds) after
    #  which it expires and the network returns to normal.
    #
    #  Effect: attacker's scan data for that port becomes invalid.
    #  Legitimate traffic: since the service is not actually on that
    #  port in the simulation, the drop rule does not affect real users.
    # ------------------------------------------------------------------
    def _port_hop(self, datapath, dst_port_counts):
        if not dst_port_counts:
            return

        # Identify the most-targeted port
        target_port = dst_port_counts.most_common(1)[0][0]
        new_port    = random.choice(HOP_PORTS)

        parser  = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Install DROP rule for traffic to the scanned port
        # hard_timeout means the rule auto-expires after HOP_RULE_TIMEOUT seconds
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=6,
                                tcp_dst=target_port)
        mod = parser.OFPFlowMod(
            datapath     = datapath,
            priority     = 10,          # higher than normal forwarding (priority 1)
            match        = match,
            instructions = [],          # empty instructions = DROP
            hard_timeout = HOP_RULE_TIMEOUT,
            flags        = ofproto.OFPFF_SEND_FLOW_REM
        )
        datapath.send_msg(mod)

        mutation_record = {
            'type'       : 'port_hop',
            'target_port': target_port,
            'new_port'   : new_port,
            'timeout'    : HOP_RULE_TIMEOUT,
            'time'       : time.strftime("%H:%M:%S"),
            'dpid'       : datapath.id
        }
        self.active_mutations.append(mutation_record)

        self.logger.warning(
            "[MUTATION] Port hop applied - port %d traffic blocked "
            "for %ds (rule auto-expires)",
            target_port, HOP_RULE_TIMEOUT
        )
        self.logger.warning(
            "[MUTATION] Notional new service port: %d", new_port
        )

    # ------------------------------------------------------------------
    #  MUTATION ii - FLOW RULE REWRITE (SOURCE BLOCK)
    #
    #  Identifies the top offending source IP and installs a
    #  high-priority DROP rule for all traffic from that IP.
    #  Also has a hard timeout so legitimate users are not permanently
    #  blocked if they were misclassified.
    # ------------------------------------------------------------------
    def _block_source(self, datapath, src_ip_counts,
                      connection_tracker, trigger):
        # Identify the most active source IP
        if not src_ip_counts:
            return

        offender_ip = src_ip_counts.most_common(1)[0][0]

        parser  = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Install DROP rule for all traffic from the offending IP
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=offender_ip)
        mod = parser.OFPFlowMod(
            datapath     = datapath,
            priority     = 10,
            match        = match,
            instructions = [],          # empty = DROP
            hard_timeout = BLOCK_RULE_TIMEOUT,
            flags        = ofproto.OFPFF_SEND_FLOW_REM
        )
        datapath.send_msg(mod)

        mutation_record = {
            'type'       : 'source_block',
            'blocked_ip' : offender_ip,
            'trigger'    : trigger,
            'timeout'    : BLOCK_RULE_TIMEOUT,
            'time'       : time.strftime("%H:%M:%S"),
            'dpid'       : datapath.id
        }
        self.active_mutations.append(mutation_record)

        self.logger.warning(
            "[MUTATION] Source block applied - traffic from %s dropped "
            "for %ds (rule auto-expires)",
            offender_ip, BLOCK_RULE_TIMEOUT
        )

    def log_summary(self, logger):
        """Prints a summary of all mutations applied this session."""
        logger.info("\n--- Mutation Session Summary ---")
        if not self.active_mutations:
            logger.info("  No mutations applied this session.")
        else:
            for i, m in enumerate(self.active_mutations, 1):
                logger.info("  %d. %s", i, m)
        logger.info("--------------------------------\n")


# ======================================================================
#  RYU CONTROLLER
#  Handles SDN communication, feeds DetectionEngine, triggers
#  MutationEngine on confirmed malicious state.
# ======================================================================

class ShapeShiftingController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ShapeShiftingController, self).__init__(*args, **kwargs)

        # Network state
        self.mac_to_port = {}
        self.datapaths   = {}

        # Traffic feature counters - reset after every detection cycle
        self.dst_port_counts    = collections.Counter()
        self.src_ip_counts      = collections.Counter()
        self.tcp_flag_counts    = collections.Counter()
        self.connection_tracker = collections.Counter()
        self.flow_count_window  = 0

        # Subsystems
        self.detection_engine = DetectionEngine(self.logger)
        self.mutation_engine  = MutationEngine(self.logger)

        # Background threads
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

        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, priority=0, match=match, actions=actions)

    # ------------------------------------------------------------------
    #  PACKET-IN - switching + feature extraction
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

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self._add_flow(datapath, priority=1, match=match, actions=actions)
            self.flow_count_window += 1

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        )
        datapath.send_msg(out)

        # Feature extraction
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt is None:
            return

        src_ip = ip_pkt.src
        self.src_ip_counts[src_ip] += 1

        tcp_pkt = pkt.get_protocol(tcp.tcp)
        if tcp_pkt:
            flag_str = self._decode_tcp_flags(tcp_pkt.bits)
            self.dst_port_counts[tcp_pkt.dst_port] += 1
            self.tcp_flag_counts[flag_str]         += 1
            self.connection_tracker[(src_ip, tcp_pkt.dst_port)] += 1

        udp_pkt = pkt.get_protocol(udp.udp)
        if udp_pkt:
            self.dst_port_counts[udp_pkt.dst_port] += 1

    # ------------------------------------------------------------------
    #  FLOW STATS REPLY
    # ------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        flows  = ev.msg.body
        active = [f for f in flows if f.priority > 0]
        self.logger.info("[STATS] Switch %s - %d active flows",
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
        while True:
            hub.sleep(POLL_INTERVAL)
            for dp in list(self.datapaths.values()):
                dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))

    def _detection_loop(self):
        while True:
            hub.sleep(DETECTION_INTERVAL)

            result = self.detection_engine.analyse(
                dst_port_counts    = self.dst_port_counts,
                tcp_flag_counts    = self.tcp_flag_counts,
                src_ip_counts      = self.src_ip_counts,
                flow_count_window  = self.flow_count_window,
                connection_tracker = self.connection_tracker
            )

            # Reset all counters after each detection cycle
            # This ensures each cycle reflects only recent traffic,
            # preventing old data from diluting new attack signals
            self.dst_port_counts    = collections.Counter()
            self.src_ip_counts      = collections.Counter()
            self.tcp_flag_counts    = collections.Counter()
            self.connection_tracker = collections.Counter()
            self.flow_count_window  = 0

            # Trigger mutation engine if malicious state confirmed
            if result['overall_state'] == MALICIOUS:
                self.logger.warning(
                    "[DETECTION] *** MALICIOUS ACTIVITY DETECTED *** "
                    "- activating mutation engine"
                )
                self.mutation_engine.respond(
                    detection_result    = result,
                    datapaths           = self.datapaths,
                    dst_port_counts     = self.dst_port_counts,
                    src_ip_counts       = self.src_ip_counts,
                    connection_tracker  = self.connection_tracker
                )
                self.mutation_engine.log_summary(self.logger)

            elif result['overall_state'] == SUSPICIOUS:
                self.logger.warning(
                    "[DETECTION] Suspicious activity - monitoring intensified"
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
