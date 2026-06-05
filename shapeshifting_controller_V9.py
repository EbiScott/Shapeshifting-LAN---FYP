"""
Shapeshifting LAN Defence System
V7 — Final version with dashboard, live log, and integrated attack runner
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

NORMAL     = "NORMAL"
SUSPICIOUS = "SUSPICIOUS"
MALICIOUS  = "MALICIOUS"

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
#  ATTACK RUNNER
#  Imports test functions directly from test_suite.py so they run
#  in the same process with the same permissions and timing as the
#  controller. This avoids subprocess permission errors and timing
#  issues that prevented detection from triggering via the dashboard.
# ======================================================================

def run_attack(test_num, target_ip='10.0.0.4'):
    """
    Runs attack simulation by importing test functions from test_suite.py.
    Falls back to inline scapy if test_suite.py is not found.
    """
    import sys
    import os

    label_map = {
        '0': 'Normal baseline traffic',
        '1': 'Entropy SUSPICIOUS — scan 20 ports',
        '2': 'Entropy MALICIOUS — scan 100 ports',
        '3': 'SYN flood SUSPICIOUS — 30 SYN / 5 ACK',
        '4': 'SYN flood MALICIOUS — 100 SYN / 0 ACK',
        '5': 'Flow velocity SUSPICIOUS — 20 connections',
        '6': 'Flow velocity MALICIOUS — 80 connections',
        '7': 'Brute force SUSPICIOUS — 20 SSH attempts',
        '8': 'Brute force MALICIOUS — 80 SSH attempts',
    }

    label = label_map.get(str(test_num), 'Unknown test')
    _log('ATTACK', f'--- Starting: {label} ---')
    _log('ATTACK', f'    Target: {target_ip}')

    try:
        # Add FYP directory to path so test_suite can be imported
        fyp_path = os.path.expanduser('~/FYP')
        if fyp_path not in sys.path:
            sys.path.insert(0, fyp_path)

        # Import test_suite and patch its target_ip
        import importlib
        import test_suite as ts

        # Override target IP in the test_suite module
        ts.target_ip = target_ip

        fn_map = {
            '0': ts.normal_traffic,
            '1': ts.test_entropy_suspicious,
            '2': ts.test_entropy_malicious,
            '3': ts.test_syn_suspicious,
            '4': ts.test_syn_malicious,
            '5': ts.test_flow_suspicious,
            '6': ts.test_flow_malicious,
            '7': ts.test_brute_suspicious,
            '8': ts.test_brute_malicious,
        }

        fn = fn_map.get(str(test_num))
        if fn is None:
            _log('ATTACK', f'    Unknown test number: {test_num}')
            return

        # Redirect stdout so print() calls go to the log
        import io
        old_stdout = sys.stdout
        sys.stdout = buf = io.StringIO()
        try:
            fn()
        finally:
            sys.stdout = old_stdout
        output = buf.getvalue()
        for line in output.strip().split('\n'):
            if line.strip():
                _log('ATTACK', f'    {line}')

    except ImportError:
        _log('ATTACK', '    test_suite.py not found — using inline scapy')
        _run_inline_attack(test_num, target_ip)
    except Exception as e:
        _log('ATTACK', f'    Error: {e}')

    _log('ATTACK', f'--- Complete: {label} ---')
    _log('ATTACK', '    Detection cycle runs every 10s — watch for state change')


def _run_inline_attack(test_num, target_ip):
    """Fallback inline scapy attack if test_suite.py is not available."""
    try:
        from scapy.all import IP, TCP, send
        import random as rnd

        n = str(test_num)
        if n == '0':
            for _ in range(10):
                send(IP(dst=target_ip)/TCP(dport=rnd.choice([80,443,22,53]),flags='S'),verbose=0)
                time.sleep(0.3)
            for _ in range(8):
                send(IP(dst=target_ip)/TCP(dport=80,flags='A'),verbose=0)
        elif n == '1':
            for p in range(1,21):
                send(IP(dst=target_ip)/TCP(dport=p,flags='S'),verbose=0)
                time.sleep(0.05)
        elif n == '2':
            for p in range(1,101):
                send(IP(dst=target_ip)/TCP(dport=p,flags='S'),verbose=0)
                time.sleep(0.01)
        elif n == '3':
            for _ in range(30): send(IP(dst=target_ip)/TCP(dport=80,flags='S'),verbose=0)
            for _ in range(5):  send(IP(dst=target_ip)/TCP(dport=80,flags='A'),verbose=0)
        elif n == '4':
            for _ in range(100): send(IP(dst=target_ip)/TCP(dport=80,flags='S'),verbose=0)
        elif n == '5':
            for _ in range(20):
                send(IP(dst=target_ip)/TCP(dport=rnd.randint(1024,65535),flags='S'),verbose=0)
                time.sleep(0.02)
        elif n == '6':
            for _ in range(80):
                send(IP(dst=target_ip)/TCP(dport=rnd.randint(1024,65535),flags='S'),verbose=0)
                time.sleep(0.005)
        elif n == '7':
            for _ in range(20):
                send(IP(dst=target_ip)/TCP(dport=22,flags='S'),verbose=0)
                time.sleep(0.1)
        elif n == '8':
            for _ in range(80):
                send(IP(dst=target_ip)/TCP(dport=22,flags='S'),verbose=0)
                time.sleep(0.01)
    except Exception as e:
        _log('ATTACK', f'    Inline scapy error: {e}')


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
        if entropy >= ENTROPY_MALICIOUS:   return MALICIOUS, entropy
        elif entropy >= ENTROPY_SUSPICIOUS: return SUSPICIOUS, entropy
        return NORMAL, entropy

    def _check_syn_ratio(self, tcp_flag_counts):
        syn_count = sum(c for f, c in tcp_flag_counts.items() if 'SYN' in f)
        ack_count = sum(c for f, c in tcp_flag_counts.items() if 'ACK' in f)
        ratio = float(syn_count) if ack_count == 0 else syn_count / ack_count
        if ratio >= SYN_RATIO_MALICIOUS:   return MALICIOUS, ratio
        elif ratio >= SYN_RATIO_SUSPICIOUS: return SUSPICIOUS, ratio
        return NORMAL, ratio

    def _check_flow_velocity(self, flow_count_window):
        if flow_count_window >= FLOW_RATE_MALICIOUS:   return MALICIOUS, flow_count_window
        elif flow_count_window >= FLOW_RATE_SUSPICIOUS: return SUSPICIOUS, flow_count_window
        return NORMAL, flow_count_window

    def _check_brute_force(self, connection_tracker):
        if not connection_tracker:
            return NORMAL, None
        worst_pair  = max(connection_tracker, key=connection_tracker.get)
        worst_count = connection_tracker[worst_pair]
        detail = {'src_ip': worst_pair[0], 'dst_port': worst_pair[1],
                  'count': worst_count}
        if worst_count >= BRUTE_FORCE_MALICIOUS:   return MALICIOUS, detail
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

        msg = f"*** MUTATION ENGINE ACTIVATED | Trigger: {trigger} | {time.strftime('%H:%M:%S')}"
        self.logger.warning(msg)
        _log('MUTATION', msg)

        for dpid, datapath in datapaths.items():
            if trigger == 'port_entropy':
                self._port_hop(datapath, dst_port_counts)
            elif trigger in ('syn_ratio', 'brute_force', 'flow_velocity'):
                self._block_source(datapath, src_ip_counts,
                                   connection_tracker, trigger)

    def _port_hop(self, datapath, dst_port_counts):
        if not dst_port_counts:
            _log('MUTATION', '[MUTATION] Port hop skipped -- no port data')
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

        record = {
            'type': 'port_hop', 'target_port': target_port,
            'new_port': new_port, 'timeout': HOP_RULE_TIMEOUT,
            'time': time.strftime("%H:%M:%S"), 'dpid': datapath.id
        }
        self.active_mutations.append(record)
        with _state_lock:
            _shared_state['mutations'].append(record)

        msg = f"[MUTATION] Port hop -- port {target_port} blocked for {HOP_RULE_TIMEOUT}s | new port: {new_port}"
        self.logger.warning(msg)
        _log('MUTATION', msg)

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
            datapath=datapath, priority=10, match=match,
            instructions=[], hard_timeout=BLOCK_RULE_TIMEOUT,
            flags=ofproto.OFPFF_SEND_FLOW_REM
        )
        datapath.send_msg(mod)

        record = {
            'type': 'source_block', 'blocked_ip': offender_ip,
            'trigger': trigger, 'timeout': BLOCK_RULE_TIMEOUT,
            'time': time.strftime("%H:%M:%S"), 'dpid': datapath.id
        }
        self.active_mutations.append(record)
        with _state_lock:
            _shared_state['mutations'].append(record)

        msg = f"[MUTATION] Source block -- {offender_ip} dropped for {BLOCK_RULE_TIMEOUT}s"
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
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
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
            self._send_file('/home/mininet/FYP/dashboard.html', 'text/html')

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path.startswith('/api/test/'):
            parts    = self.path.split('/')
            raw      = parts[-1]
            test_num = raw.split('?')[0]
            target   = '10.0.0.4'
            if 'target=' in self.path:
                target = self.path.split('target=')[1].split('&')[0]

            t = threading.Thread(
                target=run_attack,
                args=(test_num, target),
                daemon=True
            )
            t.start()
            self._send_json({'status': 'running', 'test': test_num,
                             'target': target})
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
        msg    = f"[STATS] Switch {ev.msg.datapath.id} -- {len(active)} active non-TCP flows"
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
                if len(_shared_state['history']) > 20:
                    _shared_state['history'].pop(0)

            if result['overall_state'] == MALICIOUS:
                msg = "[DETECTION] *** MALICIOUS ACTIVITY DETECTED *** -- activating mutation engine"
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
