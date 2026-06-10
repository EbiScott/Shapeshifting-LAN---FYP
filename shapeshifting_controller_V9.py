"""
Shapeshifting LAN Defence System
V9 — True port redirection + persistent history

Port hopping now implements genuine OpenFlow traffic redirection:
    - Incoming traffic to the scanned port gets its TCP dst_port
      rewritten to the new hop port before forwarding to the server.
    - Return traffic from the server on the new port gets its TCP
      src_port rewritten back to the original port before forwarding
      to the client.
    - The client sees a continuous service on the original port.
    - The attacker's scan data becomes stale immediately.
    - The server (h4) services the request on the new port, which it
      is already listening on (topology.py starts HTTP on all hop ports).

This matches the Chapter 3 description:
    "Port hopping involved the controller installing a new OpenFlow
    flow rule redirecting traffic destined for the original service
    port to a newly assigned port, effectively relocating the service
    without modifying the host operating system."
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
import json
import os
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler


# ======================================================================
#  THRESHOLDS
# ======================================================================

ENTROPY_SUSPICIOUS     = 3.0
ENTROPY_MALICIOUS      = 4.5
SYN_RATIO_SUSPICIOUS   = 3.0
SYN_RATIO_MALICIOUS    = 7.0
FLOW_RATE_SUSPICIOUS   = 15
FLOW_RATE_MALICIOUS    = 30
BRUTE_FORCE_SUSPICIOUS = 10
BRUTE_FORCE_MALICIOUS  = 25
DETECTION_INTERVAL     = 10
POLL_INTERVAL          = 10
BLOCK_RULE_TIMEOUT     = 60
HOP_RULE_TIMEOUT       = 30
HOP_PORTS              = [8080, 8443, 9000, 9090, 7070]
FLOW_IDLE_TIMEOUT      = 2
API_PORT               = 8080
MAX_LOG_LINES          = 300

SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
HISTORY_FILE = os.path.join(SCRIPT_DIR, 'detection_history.json')
MAX_HISTORY_CYCLES = 1008   # 7 days at 6 cycles/hour

NORMAL     = "NORMAL"
SUSPICIOUS = "SUSPICIOUS"
MALICIOUS  = "MALICIOUS"


# ======================================================================
#  PERSISTENT HISTORY
# ======================================================================

def load_history():
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE, 'r') as f:
            data = json.load(f)
        cutoff = time.time() - (7 * 24 * 3600)
        return [r for r in data if r.get('unix_ts', 0) >= cutoff]
    except Exception:
        return []


def save_history(history):
    try:
        with open(HISTORY_FILE, 'w') as f:
            json.dump(history[-MAX_HISTORY_CYCLES:], f)
    except Exception:
        pass


def filter_history(history, window):
    seconds = {'1h': 3600, '6h': 21600, '24h': 86400, '7d': 604800}.get(window, 3600)
    cutoff  = time.time() - seconds
    return [r for r in history if r.get('unix_ts', 0) >= cutoff]


# ======================================================================
#  SHARED STATE
# ======================================================================

_shared_state = {
    'latest_result' : None,
    'mutations'     : [],
    'packet_counts' : {'total': 0, 'tcp': 0, 'udp': 0, 'other': 0},
    'history'       : [],
    'log'           : [],
}
_state_lock = threading.Lock()


def _log(level, message):
    line = {'time': time.strftime("%H:%M:%S"), 'level': level, 'msg': message}
    with _state_lock:
        _shared_state['log'].append(line)
        if len(_shared_state['log']) > MAX_LOG_LINES:
            _shared_state['log'].pop(0)


# ======================================================================
#  DETECTION ENGINE
# ======================================================================

class DetectionEngine:

    def __init__(self, logger):
        self.logger = logger

    def analyse(self, dst_port_counts, tcp_flag_counts,
                src_ip_counts, flow_count_window, connection_tracker):

        results = {}

        results['entropy_state'], results['entropy_value'] = \
            self._check_port_entropy(dst_port_counts)
        results['syn_state'], results['syn_ratio'] = \
            self._check_syn_ratio(tcp_flag_counts)
        results['flow_state'], results['flow_count'] = \
            self._check_flow_velocity(flow_count_window)
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

        results['trigger']   = self._identify_trigger(results)
        results['timestamp'] = time.strftime("%H:%M:%S")
        results['unix_ts']   = time.time()
        results['top_ports'] = list(dst_port_counts.most_common(5))
        results['top_ips']   = list(src_ip_counts.most_common(5))

        self._log_results(results)
        return results

    def _check_port_entropy(self, dst_port_counts):
        total = sum(dst_port_counts.values())
        if total == 0:
            return NORMAL, 0.0
        entropy = 0.0
        for count in dst_port_counts.values():
            p = count / total
            entropy -= p * math.log2(p)
        if entropy >= ENTROPY_MALICIOUS:    return MALICIOUS, entropy
        elif entropy >= ENTROPY_SUSPICIOUS: return SUSPICIOUS, entropy
        return NORMAL, entropy

    def _check_syn_ratio(self, tcp_flag_counts):
        syn_count = sum(c for f, c in tcp_flag_counts.items() if 'SYN' in f)
        ack_count = sum(c for f, c in tcp_flag_counts.items() if 'ACK' in f)
        ratio = float(syn_count) if ack_count == 0 else syn_count / ack_count
        if ratio >= SYN_RATIO_MALICIOUS:    return MALICIOUS, ratio
        elif ratio >= SYN_RATIO_SUSPICIOUS: return SUSPICIOUS, ratio
        return NORMAL, ratio

    def _check_flow_velocity(self, flow_count_window):
        if flow_count_window >= FLOW_RATE_MALICIOUS:    return MALICIOUS, flow_count_window
        elif flow_count_window >= FLOW_RATE_SUSPICIOUS: return SUSPICIOUS, flow_count_window
        return NORMAL, flow_count_window

    def _check_brute_force(self, connection_tracker):
        if not connection_tracker:
            return NORMAL, None
        worst_pair  = max(connection_tracker, key=connection_tracker.get)
        worst_count = connection_tracker[worst_pair]
        detail = {'src_ip': worst_pair[0], 'dst_port': worst_pair[1],
                  'count': worst_count}
        if worst_count >= BRUTE_FORCE_MALICIOUS:    return MALICIOUS, detail
        elif worst_count >= BRUTE_FORCE_SUSPICIOUS: return SUSPICIOUS, detail
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
        lines = [
            "=" * 54,
            f"  DETECTION CYCLE  [{r['timestamp']}]",
            "=" * 54,
            f"  [i]   Port entropy  : {r['entropy_value']:.3f} bits -> {r['entropy_state']}",
            f"  [ii]  SYN/ACK ratio : {r['syn_ratio']:.2f} -> {r['syn_state']}",
            f"  [iii] Flow velocity : {r['flow_count']} SYNs -> {r['flow_state']}",
            f"  [iv]  Brute force   : {r['brute_detail']} -> {r['brute_state']}",
            f"  OVERALL STATE       : {r['overall_state']}",
        ]
        if r['overall_state'] != NORMAL:
            lines.append(f"  TRIGGER             : {r['trigger']}")
        lines.append("=" * 54)
        for line in lines:
            self.logger.info(line)
            _log('DETECTION', line)


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

        msg = (f"*** MUTATION ENGINE ACTIVATED | "
               f"Trigger: {trigger} | {time.strftime('%H:%M:%S')}")
        self.logger.warning(msg)
        _log('MUTATION', msg)

        for dpid, datapath in datapaths.items():
            if trigger == 'port_entropy':
                self._port_hop(datapath, dst_port_counts)
            elif trigger in ('syn_ratio', 'brute_force', 'flow_velocity'):
                self._block_source(datapath, src_ip_counts,
                                   connection_tracker, trigger)

    # ------------------------------------------------------------------
    #  MUTATION i — TRUE PORT REDIRECTION
    #
    #  Installs two OpenFlow rules with hard_timeout:
    #
    #  Rule A (priority 10) — inbound:
    #    Match:   eth_type=IPv4, ip_proto=TCP, tcp_dst=original_port
    #    Action:  SET_FIELD tcp_dst=new_port, OUTPUT to server port
    #
    #  Rule B (priority 10) — outbound return traffic:
    #    Match:   eth_type=IPv4, ip_proto=TCP, tcp_src=new_port
    #    Action:  SET_FIELD tcp_src=original_port, OUTPUT to flood
    #
    #  Both rules expire after HOP_RULE_TIMEOUT seconds, after which
    #  normal forwarding resumes automatically.
    #
    #  Effect: the client sees traffic on the original port throughout.
    #  The attacker's scan data for the original port becomes stale.
    #  The server continues serving from the new port transparently.
    # ------------------------------------------------------------------
    def _port_hop(self, datapath, dst_port_counts):
        if not dst_port_counts:
            _log('MUTATION', '[MUTATION] Port hop skipped -- no port data')
            return

        original_port = dst_port_counts.most_common(1)[0][0]
        new_port      = random.choice(HOP_PORTS)
        parser        = datapath.ofproto_parser
        ofproto       = datapath.ofproto

        # Rule A — rewrite incoming traffic dst port
        match_in = parser.OFPMatch(
            eth_type=0x0800,
            ip_proto=6,
            tcp_dst=original_port
        )
        actions_in = [
            parser.OFPActionSetField(tcp_dst=new_port),
            parser.OFPActionOutput(ofproto.OFPP_NORMAL)
        ]
        inst_in = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions_in)]
        mod_in = parser.OFPFlowMod(
            datapath     = datapath,
            priority     = 10,
            match        = match_in,
            instructions = inst_in,
            hard_timeout = HOP_RULE_TIMEOUT,
            flags        = ofproto.OFPFF_SEND_FLOW_REM
        )
        datapath.send_msg(mod_in)

        # Rule B — rewrite outgoing return traffic src port
        match_out = parser.OFPMatch(
            eth_type=0x0800,
            ip_proto=6,
            tcp_src=new_port
        )
        actions_out = [
            parser.OFPActionSetField(tcp_src=original_port),
            parser.OFPActionOutput(ofproto.OFPP_NORMAL)
        ]
        inst_out = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions_out)]
        mod_out = parser.OFPFlowMod(
            datapath     = datapath,
            priority     = 10,
            match        = match_out,
            instructions = inst_out,
            hard_timeout = HOP_RULE_TIMEOUT,
            flags        = ofproto.OFPFF_SEND_FLOW_REM
        )
        datapath.send_msg(mod_out)

        record = {
            'type'         : 'port_hop',
            'original_port': original_port,
            'new_port'     : new_port,
            'timeout'      : HOP_RULE_TIMEOUT,
            'time'         : time.strftime("%H:%M:%S"),
            'dpid'         : datapath.id
        }
        self.active_mutations.append(record)
        with _state_lock:
            _shared_state['mutations'].append(record)

        msg = (f"[MUTATION] Port hop -- traffic redirected from port "
               f"{original_port} to port {new_port} for {HOP_RULE_TIMEOUT}s "
               f"(auto-expires, both inbound and return rules installed)")
        self.logger.warning(msg)
        _log('MUTATION', msg)

    # ------------------------------------------------------------------
    #  MUTATION ii — FLOW RULE REWRITE (SOURCE BLOCK)
    #
    #  Installs a timed DROP rule for the top offending source IP.
    #  Rule auto-expires after BLOCK_RULE_TIMEOUT seconds.
    # ------------------------------------------------------------------
    def _block_source(self, datapath, src_ip_counts,
                      connection_tracker, trigger):
        if not src_ip_counts:
            _log('MUTATION', '[MUTATION] Source block skipped -- no IP data')
            return

        offender_ip = src_ip_counts.most_common(1)[0][0]
        parser      = datapath.ofproto_parser
        ofproto     = datapath.ofproto

        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=offender_ip)
        mod = parser.OFPFlowMod(
            datapath     = datapath,
            priority     = 10,
            match        = match,
            instructions = [],
            hard_timeout = BLOCK_RULE_TIMEOUT,
            flags        = ofproto.OFPFF_SEND_FLOW_REM
        )
        datapath.send_msg(mod)

        record = {
            'type'      : 'source_block',
            'blocked_ip': offender_ip,
            'trigger'   : trigger,
            'timeout'   : BLOCK_RULE_TIMEOUT,
            'time'      : time.strftime("%H:%M:%S"),
            'dpid'      : datapath.id
        }
        self.active_mutations.append(record)
        with _state_lock:
            _shared_state['mutations'].append(record)

        msg = (f"[MUTATION] Source block -- traffic from {offender_ip} "
               f"dropped for {BLOCK_RULE_TIMEOUT}s (auto-expires)")
        self.logger.warning(msg)
        _log('MUTATION', msg)

    def log_summary(self, logger):
        if not self.active_mutations:
            _log('MUTATION', '  No mutations applied this session.')
        else:
            for i, m in enumerate(self.active_mutations, 1):
                _log('MUTATION', f"  {i}. {m}")


# ======================================================================
#  REST API SERVER
# ======================================================================

class DashboardHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        pass

    def _send_json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path, content_type):
        try:
            with open(path, 'rb') as f:
                body = f.read()
            self.send_response(200)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', len(body))
            self.end_headers()
            self.wfile.write(body)
        except FileNotFoundError:
            self.send_response(404)
            self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_GET(self):
        if self.path == '/api/status':
            with _state_lock:
                data = {
                    'latest'  : _shared_state['latest_result'],
                    'history' : _shared_state['history'][-20:],
                    'packets' : _shared_state['packet_counts'],
                }
            self._send_json(data)

        elif self.path.startswith('/api/history'):
            window = '1h'
            if '?window=' in self.path:
                window = self.path.split('?window=')[1].split('&')[0]
            with _state_lock:
                history = list(_shared_state['history'])
            filtered = filter_history(history, window)
            self._send_json({'history': filtered, 'window': window,
                             'count': len(filtered)})

        elif self.path == '/api/mutations':
            with _state_lock:
                data = {'mutations': _shared_state['mutations'][-50:]}
            self._send_json(data)

        elif self.path.startswith('/api/log'):
            since = 0
            if '?since=' in self.path:
                try:
                    since = int(self.path.split('?since=')[1].split('&')[0])
                except:
                    since = 0
            with _state_lock:
                log   = _shared_state['log']
                total = len(log)
                lines = log[since:]
            self._send_json({'lines': lines, 'total': total})

        elif self.path == '/' or self.path == '/index.html':
            self._send_file(
                os.path.join(SCRIPT_DIR, 'dashboard.html'), 'text/html')

        else:
            self.send_response(404)
            self.end_headers()


def run_api_server():
    server = HTTPServer(('0.0.0.0', API_PORT), DashboardHandler)
    server.serve_forever()


# ======================================================================
#  RYU CONTROLLER
# ======================================================================

class ShapeShiftingController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ShapeShiftingController, self).__init__(*args, **kwargs)

        self.mac_to_port = {}
        self.datapaths   = {}

        self.dst_port_counts    = collections.Counter()
        self.src_ip_counts      = collections.Counter()
        self.tcp_flag_counts    = collections.Counter()
        self.connection_tracker = collections.Counter()
        self.flow_count_window  = 0

        self.detection_engine = DetectionEngine(self.logger)
        self.mutation_engine  = MutationEngine(self.logger)

        loaded = load_history()
        with _state_lock:
            _shared_state['history'] = loaded

        msg = f"[HISTORY] Loaded {len(loaded)} cycles from {HISTORY_FILE}"
        self.logger.info(msg)
        _log('INFO', msg)

        self.monitor_thread   = hub.spawn(self._monitor_loop)
        self.detection_thread = hub.spawn(self._detection_loop)

        api_thread = threading.Thread(target=run_api_server, daemon=True)
        api_thread.start()

        msg = f"[API] Dashboard running on http://0.0.0.0:{API_PORT}"
        self.logger.info(msg)
        _log('INFO', msg)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser

        self.datapaths[datapath.id] = datapath
        msg = f"[SETUP] Switch {datapath.id} connected"
        self.logger.info(msg)
        _log('INFO', msg)

        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, priority=0, match=match, actions=actions,
                       idle_timeout=0)

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

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port
        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions  = [parser.OFPActionOutput(out_port)]

        ip_pkt  = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp) if ip_pkt else None

        if tcp_pkt:
            pass  # no flow rule — every TCP packet hits controller
        elif out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self._add_flow(datapath, priority=1, match=match, actions=actions,
                           idle_timeout=FLOW_IDLE_TIMEOUT)

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        )
        datapath.send_msg(out)

        with _state_lock:
            _shared_state['packet_counts']['total'] += 1
            if tcp_pkt:
                _shared_state['packet_counts']['tcp'] += 1
            elif pkt.get_protocol(udp.udp):
                _shared_state['packet_counts']['udp'] += 1
            else:
                _shared_state['packet_counts']['other'] += 1

        if ip_pkt is None:
            return

        src_ip = ip_pkt.src
        self.src_ip_counts[src_ip] += 1

        if tcp_pkt:
            flag_str = self._decode_tcp_flags(tcp_pkt.bits)
            dst_port = tcp_pkt.dst_port
            self.dst_port_counts[dst_port]              += 1
            self.tcp_flag_counts[flag_str]              += 1
            self.connection_tracker[(src_ip, dst_port)] += 1
            if (tcp_pkt.bits & 0x02) and not (tcp_pkt.bits & 0x10):
                self.flow_count_window += 1

        udp_pkt = pkt.get_protocol(udp.udp)
        if udp_pkt:
            self.dst_port_counts[udp_pkt.dst_port] += 1

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        flows  = ev.msg.body
        active = [f for f in flows if f.priority == 1]
        msg    = (f"[STATS] Switch {ev.msg.datapath.id} -- "
                  f"{len(active)} active non-TCP flows")
        self.logger.info(msg)
        _log('INFO', msg)

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

            with _state_lock:
                _shared_state['latest_result'] = result
                _shared_state['history'].append(result)
                cutoff = time.time() - (7 * 24 * 3600)
                _shared_state['history'] = [
                    r for r in _shared_state['history']
                    if r.get('unix_ts', 0) >= cutoff
                ]
                snapshot = list(_shared_state['history'])

            threading.Thread(
                target=save_history, args=(snapshot,), daemon=True
            ).start()

            if result['overall_state'] == MALICIOUS:
                msg = ("[DETECTION] *** MALICIOUS ACTIVITY DETECTED *** "
                       "-- activating mutation engine")
                self.logger.warning(msg)
                _log('WARNING', msg)
                self.mutation_engine.respond(
                    detection_result   = result,
                    datapaths          = self.datapaths,
                    dst_port_counts    = self.dst_port_counts,
                    src_ip_counts      = self.src_ip_counts,
                    connection_tracker = self.connection_tracker
                )
                self.mutation_engine.log_summary(self.logger)

            elif result['overall_state'] == SUSPICIOUS:
                msg = "[DETECTION] Suspicious activity -- monitoring intensified"
                self.logger.warning(msg)
                _log('WARNING', msg)
            else:
                msg = "[DETECTION] Traffic state: NORMAL"
                self.logger.info(msg)
                _log('INFO', msg)

            self.dst_port_counts    = collections.Counter()
            self.src_ip_counts      = collections.Counter()
            self.tcp_flag_counts    = collections.Counter()
            self.connection_tracker = collections.Counter()
            self.flow_count_window  = 0

    def _add_flow(self, datapath, priority, match, actions,
                  idle_timeout=FLOW_IDLE_TIMEOUT):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        inst    = [parser.OFPInstructionActions(
                       ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=priority, match=match,
            instructions=inst, idle_timeout=idle_timeout
        )
        datapath.send_msg(mod)

    @staticmethod
    def _decode_tcp_flags(bits):
        names = [(0x01,'FIN'),(0x02,'SYN'),(0x04,'RST'),
                 (0x08,'PSH'),(0x10,'ACK'),(0x20,'URG')]
        return '|'.join(name for bit,name in names if bits & bit) or 'NONE'
