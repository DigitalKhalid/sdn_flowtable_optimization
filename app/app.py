from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from datetime import datetime
from ryu import cfg
import time
import random
import csv
from timeout_predictor import timeout_predictor

flow_cookie = 0
gflows = []
min_idle_timeout = 1
max_idle_timeout = 11

#flow_cookie = 0

flow_cookie = {}

#flow serial number
def get_cookie(dpid):
    global flow_cookie
    flow_cookie.setdefault(dpid, 0)
    flow_cookie[dpid] = flow_cookie[dpid] + 1
    return  flow_cookie[dpid]


def get_time():
    return time.strftime("%H:%M:%S", time.localtime())



class FlowEvictionApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FlowEvictionApp, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

        self.flows = {}

        # reading input from config file.
        CONF = cfg.CONF
        CONF.register_opts([
            cfg.IntOpt('threshold', default=80, help = ('threshold')),
            cfg.StrOpt('algorithm', default='FIFO', help = ('Algorithm')),
            cfg.IntOpt('idle_timeout', default = min_idle_timeout, help = ('idle timeout')),
            cfg.IntOpt('hard_timeout', default = max_idle_timeout, help = ('hard timeout')),
            ])

        self.threshold = CONF.threshold
        self.algorithm = CONF.algorithm
        self.idle_timeout = CONF.idle_timeout
        self.hard_timeout = CONF.hard_timeout
        self.logger.info("starting with threshold %d   algorithm %s",self.threshold,  self.algorithm)
        self.logger.info("idle timeouot %d  hard timeout %s",self.idle_timeout,  self.hard_timeout)



    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.flows.setdefault(datapath.id,{})

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def _print_active_flows(self,dpid):
        self.logger.info("Datapath %d  Total Active flows : %d ", dpid, len(self.flows[dpid]))


    # def random_algo(self, datapath):
    #     dpid = datapath.id
    #     key = random.choice(list(self.flows[dpid]))
    #     self.logger.info("Datapath %d random_algo - Selected flow Cookie : %d for delete ", dpid, key)
    #     self.__delete_flow(datapath, key)
    #     #remove from flowmgmt
    #     del self.flows[dpid][key]


    # def fifo_algo(self, datapath):
    #     dpid = datapath.id
    #     #identify the lowest key.
    #     key = min(list(self.flows[dpid]))
    #     self.logger.info("Datapath %d fifo_algo - Selected flow Cookie : %d for delete ", dpid, key)
    #     self.__delete_flow(datapath, key)
    #     #remove from flowmgmt
    #     del self.flows[dpid][key]

    # def lru_algo(self,datapath):
    #     pass     


    # def __delete_flow(self, datapath, cookie_id):
    #     '''
    #     delete flow function.
    #     '''
    #     ofproto = datapath.ofproto
    #     parser = datapath.ofproto_parser
    #     instructions = []
    #     mod = parser.OFPFlowMod(datapath=datapath,
    #                             cookie=cookie_id,
    #                             cookie_mask=0xFFFFFFFFFFFFFFFF,
    #                             table_id=ofproto.OFPTT_ALL,
    #                             command=ofproto.OFPFC_DELETE,
    #                             out_port=ofproto.OFPP_ANY, 
    #                             out_group=ofproto.OFPG_ANY,
    #                             instructions=[])
    #     datapath.send_msg(mod)
    #     #self.logger.info("deleted flow %s", mod)


    def perform_flow_check(self, datapath):
        dpid = datapath.id
        total_active_flows = len(self.flows[dpid])
        if total_active_flows >= self.threshold :
            self.logger.info("Flow Threshold %d reached in datapath id  %d" ,self.threshold, dpid)
            if self.algorithm == "RANDOM":
                self.random_algo(datapath)
            elif self.algorithm == "FIFO":
                self.fifo_algo(datapath)
            elif self.algorithm == "LRU":
                self.lru_algo(datapath)


    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto

        if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
            reason = 'IDLE TIMEOUT'
        elif msg.reason == ofp.OFPRR_HARD_TIMEOUT:
            reason = 'HARD TIMEOUT'
        elif msg.reason == ofp.OFPRR_DELETE:
            reason = 'DELETE'
        elif msg.reason == ofp.OFPRR_GROUP_DELETE:
            reason = 'GROUP DELETE'
        else:
            reason = 'unknown'
        '''
        self.logger.info('OFPFlowRemoved received: '
                          'cookie=%d priority=%d reason=%s table_id=%d '
                          'duration_sec=%d duration_nsec=%d '
                          'idle_timeout=%d hard_timeout=%d '
                          'packet_count=%d byte_count=%d match.fields=%s',
                          msg.cookie, msg.priority, reason, msg.table_id,
                          msg.duration_sec, msg.duration_nsec,
                          msg.idle_timeout, msg.hard_timeout,
                          msg.packet_count, msg.byte_count, msg.match)
        '''
        #self._delete_flow(dp.id, msg.cookie)
        if msg.cookie in self.flows[dp.id]:
            del self.flows[dp.id][msg.cookie]
        self._print_active_flows(dp.id)


    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle = min_idle_timeout, hard = max_idle_timeout):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        cookie_id = get_cookie(datapath.id)

        idle = timeout_predictor(match, min_idle_timeout, max_idle_timeout)

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, cookie=cookie_id, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    idle_timeout=idle, hard_timeout=hard, flags=ofproto.OFPFF_SEND_FLOW_REM,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, cookie=cookie_id, priority=priority,
                                    idle_timeout=idle, hard_timeout=hard, flags=ofproto.OFPFF_SEND_FLOW_REM,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
        
        if cookie_id !=1 :
            #self.flows[datapath.id][cookie_id] = datetime.now()
            self.flows[datapath.id][cookie_id] = time.time()
            self._print_active_flows(datapath.id)
            #self.logger.info("New flow created : cookie %d time %s ",cookie_id, self.flows[datapath.id][cookie_id] )
        #check and perform flow removal
        self.perform_flow_check(datapath)


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
        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:

            # check IP Protocol and create a match for IP
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocol(ipv4.ipv4)
                srcip = ip.src
                dstip = ip.dst
                protocol = ip.proto
                # if ICMP Protocol
                if protocol == in_proto.IPPROTO_ICMP:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol)

                #  if TCP Protocol
                elif protocol == in_proto.IPPROTO_TCP:
                    t = pkt.get_protocol(tcp.tcp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol, tcp_src=t.src_port, tcp_dst=t.dst_port,)

                #  If UDP Protocol
                elif protocol == in_proto.IPPROTO_UDP:
                    u = pkt.get_protocol(udp.udp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol, udp_src=u.src_port, udp_dst=u.dst_port,)            

                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id, idle=self.idle_timeout, hard=self.hard_timeout)
                    return
                
                else:
                    self.add_flow(datapath, 1, match, actions, idle=self.idle_timeout, hard=self.hard_timeout)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
