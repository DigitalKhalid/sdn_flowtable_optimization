from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, tcp, udp, in_proto
from ryu.lib.packet import ether_types
import joblib
import warnings
import csv
import time
import datetime
from vn_settings import *


warnings.filterwarnings("ignore")

flow_cookie = {}

#flow serial number
def get_cookie(dpid):
    global flow_cookie
    flow_cookie.setdefault(dpid, 0)
    flow_cookie[dpid] = flow_cookie[dpid] + 1
    return flow_cookie[dpid]


class my_controller(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(my_controller, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.flows = {}
        self.flow_entries = 0

        self.idle_timeout = fixed_timeout
        # self.hard_timeout = max_timeout
        self.threshold = flow_table_threshold * threshold_safe_limit / 100
        self.start_time = int(time.time())
        
        # Load the machine learning model
        self.model = joblib.load(ml_model_file)
        self.scaler = joblib.load(ml_scaler_file)

        columns = ['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'pkt_size', 'predicted_timeout']
        with open(prediction_log_file, 'w', newline = '') as logs:
            writer = csv.writer(logs)
            writer.writerow(columns)

        columns = ['timestamp', 'dpid', 'flows', 'eviction_reason']
        with open(flowtable_log_file, 'w', newline = '') as logs:
            writer = csv.writer(logs)
            writer.writerow(columns)

        self.summary_created = False


    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle = fixed_timeout):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        
        cookie_id = get_cookie(datapath.id)

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, cookie=cookie_id, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    idle_timeout=idle, flags=ofproto.OFPFF_SEND_FLOW_REM,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, cookie=cookie_id, priority=priority,
                                    idle_timeout=idle, flags=ofproto.OFPFF_SEND_FLOW_REM,
                                    match=match, instructions=inst)
        
        datapath.send_msg(mod)

        if cookie_id != 1 :
            self.flows[datapath.id][cookie_id] = time.time()

        self.perform_flow_check(datapath)
        

    def remove_flow_entry(self, cookie_id, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Create a FlowMod message with the DELETE command
        mod = parser.OFPFlowMod(
                datapath=datapath,
                cookie=cookie_id,
                cookie_mask=0xFFFFFFFFFFFFFFFF,
                table_id=ofproto.OFPTT_ALL,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY
            )

        # Send the FlowMod message to remove the flow entry
        datapath.send_msg(mod)


    def proactive_deletion(self, datapath, deletion_count):
        # Sort the dictionary by timestamp
        LRU_flows = dict(sorted(self.flows[datapath.id].items(), key=lambda item: item[1], reverse=False))

        LRU_flows = list(LRU_flows)[:deletion_count]
        self.logger.info(f'LRU Flows: {LRU_flows}')

        for cookie_id in LRU_flows:
            self.logger.info(f'Deleting flow: Cookie ID {cookie_id}, Timestamp: {self.flows[datapath.id][cookie_id]}')
            self.remove_flow_entry(cookie_id, datapath)


    def perform_flow_check(self, datapath):
        dpid = datapath.id
        total_active_flows = len(self.flows[dpid])

        if total_active_flows >= self.threshold :
            deletion_count = int(total_active_flows - self.threshold + 1)
            self.logger.info(f'Flow threshold {self.threshold} reached in dpid {dpid}. Flow to be removed are {deletion_count}')
            self.proactive_deletion(datapath, deletion_count)


    def get_idle_timeout(self, flow_class):
        if flow_class == 1:
            timeout = timeout_short_flow
        elif flow_class == 2:
            timeout = timeout_medium_flow
        elif flow_class == 3:
            timeout = timeout_long_flow

        return timeout


    def send(self, msg, actions):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=msg.match['in_port'], actions=actions, data=data)
        datapath.send_msg(out)


    def log_ft_occupancy(self, dpid):
        flows = len(self.flows[dpid])

        if self.flow_entries != flows:
            log = [time.time(), dpid, flows]
            self.add_log(log, flowtable_log_file)
            self.flow_entries = flows


    def add_log(self, log, log_file): 
        self.logger.info(f'\nLog: {log}\n')  

        with open(log_file, 'a', newline = '') as logs:
            writer = csv.writer(logs)
            writer.writerow(log)


    def get_time(self, timestamp):
        datetime_obj = datetime.datetime.fromtimestamp(timestamp)
        dt = datetime_obj.strftime("%d-%m-%Y %H:%M:%S")

        return dt
    

    def write_summary(self):
        summary = open(simulation_summary_file, "a")
        self.logger.info('Writing summary file')
        summary.writelines([
            '\n==============================================================================================================\n',
            'Classification Overview:\n',
            '==============================================================================================================\n',
            'Machine Learning Model: Cost Effective Multiclass Decision Tree Classifier\n',
            'with best hyperparameters as:\n',
             'Class Weights: [1:1.19, 2:10, 3:16.66],\n',
            'Maximum Tree Depth: 10\n',
            'Minimum Sample Split: 3\n',
            'Criterion: Gini\n',
            'Splitter: Best\n',
            ''
            'The Evaluation Matrix are:\n',
            'Precision: 60%\n',
            'Recall: 70%\n',
            'F1 Score: 61%\n',
            'Accuracy: 81%\n',
            'The dataset is very imbalance, having 84% short flows, 10% medium flows and 6% long flows.\n',
            ''
        ])

        summary.close()


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        self.flows.setdefault(datapath.id, {})
        
        # install table-miss flow entry
        match = parser.OFPMatch()

        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        
        self.add_flow(datapath, 0, match, actions)


    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        dpid = datapath.id

        if msg.reason == ofproto.OFPRR_IDLE_TIMEOUT:
            reason = 'IDLE TIMEOUT'

        elif msg.reason == ofproto.OFPRR_HARD_TIMEOUT:
            reason = 'HARD TIMEOUT'

        elif msg.reason == ofproto.OFPRR_DELETE:
            reason = 'Deletion'

        elif msg.reason == ofproto.OFPRR_GROUP_DELETE:
            reason = 'Group Deletion'

        else:
            reason = 'unknown'

        if msg.cookie in self.flows[datapath.id]:
            del self.flows[datapath.id][msg.cookie]

            flows = len(self.flows[dpid])
            log = [time.time(), dpid, flows, reason]
            self.add_log(log, flowtable_log_file)
            self.flow_entries = flows


    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)

        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)

        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)

        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)

        if self.summary_created == False:
            self.write_summary()
            self.summary_created = True


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
            
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
            
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        # self.logger.info(f'Outport: {out_port}')
        actions = [parser.OFPActionOutput(out_port)]      

        # Check if the Ethernet frame contains an IP packet
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            # Extract the protocol
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            proto = ip_pkt.proto
            src_port = 0
            dst_port = 0

            # Check if the IP packet contains a TCP or UDP packet
            if proto == in_proto.IPPROTO_TCP: # For TCP packet
                tp_pkt = pkt.get_protocol(tcp.tcp)
                src_port = tp_pkt.src_port
                dst_port = tp_pkt.dst_port

            elif proto == in_proto.IPPROTO_UDP: # For UDP packet
                up_pkt = pkt.get_protocol(udp.udp)
                src_port = up_pkt.src_port
                dst_port = up_pkt.dst_port

            # Extract the packet size (length)
            pkt_size = len(msg.data)

            # self.logger.info(f'\nPacket injected to ingress port ML model with Features:\nSource Port: {src_port}, Destination Port: {dst_port}, Protocol: {proto}, Pkt Size: {pkt_size}\n')

            # Add flow rule to avoid packet in again
            if proto == in_proto.IPPROTO_TCP:
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip, ipv4_dst=dst_ip, ip_proto=proto, tcp_src=src_port, tcp_dst=dst_port)

            elif proto == in_proto.IPPROTO_UDP:
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip, ipv4_dst=dst_ip, ip_proto=proto, udp_src=src_port, udp_dst=dst_port)

            elif proto == in_proto.IPPROTO_ICMP:
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip, ipv4_dst=dst_ip, ip_proto=proto)
            
            if msg.cookie not in self.flows[datapath.id]:
                if predict_timeout == True:
                    features = [src_ip, dst_ip, src_port, dst_port, proto, pkt_size]
                    
                    # Use the machine learning model to predict flow type
                    features_norm = self.scaler.transform([features[2:6]])
                    flow_class = self.model.predict(features_norm)
                    flow_class = flow_class[0]

                    idle_timeout = self.get_idle_timeout(flow_class)

                    # Add Log
                    log = [time.time(), src_ip, dst_ip, src_port, dst_port, proto, pkt_size, idle_timeout]
                    self.add_log(log, prediction_log_file)

                    # Take action based on the prediction
                    if out_port != ofproto.OFPP_FLOOD:
                        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                            self.add_flow(datapath, 1, match, actions, msg.buffer_id, idle=idle_timeout)
                        
                        else:
                            self.add_flow(datapath, 1, match, actions, idle=idle_timeout)
                
                else:
                    # Add Log
                    log = [time.time(), src_ip, dst_ip, src_port, dst_port, proto, pkt_size, self.idle_timeout]
                    self.add_log(log, prediction_log_file)

                    if out_port != ofproto.OFPP_FLOOD:
                        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                            self.add_flow(datapath, 1, match, actions, msg.buffer_id, idle=self.idle_timeout)
                    
                        else:
                            self.add_flow(datapath, 1, match, actions, idle=self.idle_timeout)

        # Log Flowtable Occupancy on every packet-in
        self.log_ft_occupancy(dpid)

        self.send(msg, actions)