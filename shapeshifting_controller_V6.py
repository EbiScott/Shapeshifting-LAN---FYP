"""
Shapeshifting LAN Defence System
V6 — Packet-level detection fix

Root cause identified in V5:
    Flow stats only contained MAC-level fields (src/dst MAC, in_port).
    No ipv4_src or tcp_dst appeared because Scapy test packets share
    the same MAC-level flow once the first rule is installed.
    All subsequent packets bypassed the controller, so dst_port_counts,
    src_ip_counts, and connection_tracker were never populated.

Fix in V6:
    Flow rules are installed with idle_timeout=2 seconds.
    After 2 seconds of inactivity the rule expires and the next packet
    comes back to the controller. For attack traffic (rapid repeated
    packets) this means the controller sees a fresh packet every 2s,
    which is frequent enough to accumulate detection data reliably.

    All feature extraction happens in packet_in_handler which now
    reliably sees traffic. Flow stats are still used for flow velocity
    (active flow count) but not for IP/port counters.
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
# ======================================================================

ENTROPY_SUSPICIOUS     = 3.0
ENTROPY_MALICIOUS      = 4.5

SYN_RATIO_SUSPICIOUS   = 3.0
SYN_RATIO_MALICIOUS    = 7.0

FLOW_RATE_SUSPICIOUS   = 15
FLOW_RATE_MALICIOUS    = 30

BRUTE_FORCE_SUSPICIOUS = 8
BRUTE_FORCE_MALICIOUS  = 20

DETECTION_INTERVAL     = 10
POLL_INTERVAL          = 10

BLOCK_RULE_TIMEOUT     = 60
HOP_RULE_TIMEOUT       = 30
HOP_PORTS              = [8080, 8443, 9000, 9090, 7070]

# Flow idle timeout — rules expire after this many seconds of inactivity
# This forces packets back to the controller so detection stays active
FLOW_IDLE_TIMEOUT      = 2

NORMAL     = "NORMAL"
SUSPICIOUS = "SUSPICIOUS"
MALICIOUS  = "MALICIOUS"


# ======================================================================
#  DETECTION ENGINE
# ======================================================================

class DetectionEngine:

    def __init__(self, logger):
        self.logger = logger

    def analyse(self, dst_port_counts, tcp_flag_counts,
                src_ip_counts, active_flow_count, connection_tracker):

        results = {}

        results['entropy_state'], results['entropy_value'] = \
            self._check_port_entropy(dst_port_counts)

        results['syn_state'], results['syn_ratio'] = \
            self._check_syn_ratio(tcp_flag_counts)

        results['flow_state'] = \
            self._check_flow_velocity(active_flow_count)

        results['brute_state'], results['brute_detail'] = \
            self._check_brute_force(connection_tracker)

        all_states = [results['entropy_state'], results['syn_state'],
                      results['flow_state'],    results['brute_state']]

        if MALICIOUS in all_states:
            results['overall_state'] = MALICIOUS
        elif SUSPICIOUS in all_states:
            results['overall_state'] = SUSPICIOUS
        else:
            results['overall_state'] = NORMAL

        results['trigger'] = self._identify_trigger(results)
        self._log_results(results)
        return results

    # ------------------------------------------------------------------
    #  METHOD i — Shannon entropy on destination port distribution
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
    #  METHOD ii — SYN/ACK ratio from TCP flag counts
    #  packet_in now fires frequently enough to accumulate these reliably
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
    #  METHOD iii — Flow velocity from active flow count in stats
    # ------------------------------------------------------------------
    def _check_flow_velocity(self, active_flow_count):
        if active_flow_count >= FLOW_RATE_MALICIOUS:
            return MALICIOUS
        elif active_flow_count >= FLOW_RATE_SUSPICIOUS:
            return SUSPICIOUS
        else:
            return NORMAL

    # ------------------------------------------------------------------
    #  METHOD iv — Brute force from connection tracker
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
        self.logger.info("  [i]   Port entropy    : %.3f bits  -> %s",
                         r['entropy_value'], r['entropy_state'])
        self.logger.info("  [ii]  SYN/ACK ratio   : %.2f        -> %s",
                         r['syn_ratio'], r['syn_state'])
        self.logger.info("  [iii] Flow velocity   : %-10s  -> %s",
                         "", r['flow_state'])
        self.logger.info("  [iv]  Brute force     : %-10s  -> %s",
                         str(r['brute_detail']), r['brute_state'])
        self.logger.info("  %-30s %s", "OVERALL STATE:", r['overall_state'])
        if r['overall_state'] != NORMAL:
            self.logger.info("  %-30s %s", "TRIGGER:", r['trigger'])
        self.logger.info("=" * 60 + "\n")


# ======================================================================
#  MUTATION ENGINE
# ======================================================================

class MutationEngine:

    def __init__(self, logger):
        self.logger           = logger
        self.active_mutations = []

    def respond(self, detection_result, datapaths,
                dst_port_counts, src_ip_counts, connection_tracker):

        trigger = detection_result['trigger']
        state   = detection_result['overall_state']

        if state != MALICIOUS:
            return

        self.logger.warning("\n*** MUTATION ENGINE ACTIVATED ***")
        self.logger.warning("    Trigger : %s", trigger)
        self.logger.warning("    Time    : %s", time.strftime("%H:%M:%S"))

        for dpid, datapath in datapaths.items():
            if trigger == 'port_entropy':
                self._port_hop(datapath, dst_port_counts)
            elif trigger in ('syn_ratio', 'brute_force', 'flow_velocity'):
                self._block_source(datapath, src_ip_counts,
                                   connection_tracker, trigger)

    def _port_hop(self, datapath, dst_port_counts):
        if not dst_port_counts:
            self.logger.warning("[MUTATION] Port hop skipped -- no port data")
            return

        target_port = dst_port_counts.most_common(1)[0][0]
        new_port    = random.choice(HOP_PORTS)
        parser      = datapath.ofproto_parser
        ofproto     = datapath.ofproto

        match = parser.OFPMatch(eth_type=0x0800, ip_proto=6,
                                tcp_dst=target_port)
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=10, match=match,
            instructions=[], hard_timeout=HOP_RULE_TIMEOUT,
            flags=ofproto.OFPFF_SEND_FLOW_REM
        )
        datapath.send_msg(mod)

        self.active_mutations.append({
            'type': 'port_hop', 'target_port': target_port,
            'new_port': new_port, 'timeout': HOP_RULE_TIMEOUT,
            'time': time.strftime("%H:%M:%S"), 'dpid': datapath.id
        })
        self.logger.warning(
            "[MUTATION] Port hop -- port %d blocked for %ds",
            target_port, HOP_RULE_TIMEOUT)
        self.logger.warning(
            "[MUTATION] Notional new service port: %d", new_port)

    def _block_source(self, datapath, src_ip_counts,
                      connection_tracker, trigger):
        if not src_ip_counts:
            self.logger.warning("[MUTATION] Source block skipped -- no IP data")
            return

        offender_ip = src_ip_counts.most_common(1)[0][0]
        parser      = datapath.ofproto_parser
        ofproto     = datapath.ofproto

        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=offender_ip)
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=10, match=match,
            instructions=[], hard_timeout=BLOCK_RULE_TIMEOUT,
            flags=ofproto.OFPFF_SEND_FLOW_REM
        )
        datapath.send_msg(mod)

        self.active_mutations.append({
            'type': 'source_block', 'blocked_ip': offender_ip,
            'trigger': trigger, 'timeout': BLOCK_RULE_TIMEOUT,
            'time': time.strftime("%H:%M:%S"), 'dpid': datapath.id
        })
        self.logger.warning(
            "[MUTATION] Source block -- traffic from %s dropped for %ds",
            offender_ip, BLOCK_RULE_TIMEOUT)

    def log_summary(self, logger):
        logger.info("\n--- Mutation Session Summary ---")
        if not self.active_mutations:
            logger.info("  No mutations applied this session.")
        else:
            for i, m in enumerate(self.active_mutations, 1):
                logger.info("  %d. %s", i, m)
        logger.info("--------------------------------\n")


# ======================================================================
#  RYU CONTROLLER
# ======================================================================

class ShapeShiftingController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ShapeShiftingController, self).__init__(*args, **kwargs)

        self.mac_to_port = {}
        self.datapaths   = {}

        # Detection counters — populated in packet_in_handler
        self.dst_port_counts    = collections.Counter()
        self.src_ip_counts      = collections.Counter()
        self.tcp_flag_counts    = collections.Counter()
        self.connection_tracker = collections.Counter()

        # Flow velocity — populated in flow_stats_reply_handler
        self.active_flow_count  = 0

        self.detection_engine = DetectionEngine(self.logger)
        self.mutation_engine  = MutationEngine(self.logger)

        self.monitor_thread   = hub.spawn(self._monitor_loop)
        self.detection_thread = hub.spawn(self._detection_loop)

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

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        Handles switching AND all feature extraction.

        Flow rules are installed with idle_timeout=FLOW_IDLE_TIMEOUT (2s).
        After 2 seconds of inactivity the rule expires automatically.
        The next packet on that flow then comes back to the controller,
        allowing continuous feature extraction even for established flows.

        This ensures detection counters accumulate properly for all
        attack types, not just first packets.
        """
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

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port
        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions  = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # idle_timeout=2 means rule expires after 2s of inactivity
            # forcing the next packet back to the controller
            self._add_flow(datapath, priority=1, match=match,
                           actions=actions, idle_timeout=FLOW_IDLE_TIMEOUT)

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

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """
        Used only for flow velocity (active flow count).
        IP/port counters are now handled by packet_in_handler.
        """
        flows  = ev.msg.body
        active = [f for f in flows if f.priority == 1]
        self.active_flow_count = len(active)
        self.logger.info("[STATS] Switch %s -- %d active flows",
                         ev.msg.datapath.id, len(active))

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
                active_flow_count  = self.active_flow_count,
                connection_tracker = self.connection_tracker
            )

            # Trigger mutation BEFORE resetting counters
            if result['overall_state'] == MALICIOUS:
                self.logger.warning(
                    "[DETECTION] *** MALICIOUS ACTIVITY DETECTED *** "
                    "-- activating mutation engine"
                )
                self.mutation_engine.respond(
                    detection_result   = result,
                    datapaths          = self.datapaths,
                    dst_port_counts    = self.dst_port_counts,
                    src_ip_counts      = self.src_ip_counts,
                    connection_tracker = self.connection_tracker
                )
                self.mutation_engine.log_summary(self.logger)

            elif result['overall_state'] == SUSPICIOUS:
                self.logger.warning(
                    "[DETECTION] Suspicious activity -- monitoring intensified"
                )
            else:
                self.logger.info("[DETECTION] Traffic state: NORMAL")

            # Reset counters after mutation engine has read them
            self.dst_port_counts    = collections.Counter()
            self.src_ip_counts      = collections.Counter()
            self.tcp_flag_counts    = collections.Counter()
            self.connection_tracker = collections.Counter()

    def _add_flow(self, datapath, priority, match, actions,
                  idle_timeout=FLOW_IDLE_TIMEOUT):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        inst    = [parser.OFPInstructionActions(
                       ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath     = datapath,
            priority     = priority,
            match        = match,
            instructions = inst,
            idle_timeout = idle_timeout
        )
        datapath.send_msg(mod)

    @staticmethod
    def _decode_tcp_flags(bits):
        names = [(0x01, 'FIN'), (0x02, 'SYN'), (0x04, 'RST'),
                 (0x08, 'PSH'), (0x10, 'ACK'), (0x20, 'URG')]
        return '|'.join(name for bit, name in names if bits & bit) or 'NONE'
