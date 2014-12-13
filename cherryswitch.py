"""
A switch that content-filters HTTP traffic
"""

import cherryproxy
import logging
import struct

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.mac import haddr_to_str
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import tcp
from ryu.lib.packet import ipv4

class CherrySwitch(app_manager.RyuApp, cherryproxy.CherryProxy):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]
    
    def getBlacklist(self, filename='domain_blacklist'):
        with open(filename) as f:
            blist = f.readlines()
            f.close()
        blacklist = [x.rstrip() for x in blist]
        return blacklist

    def __init__(self, *args, **kwargs):
        self.IPADDR = '192.168.57.5'
        self.blacklist = self.getBlacklist()
        super(CherrySwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    def add_flow(self, datapath, in_port, dst, actions):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port, dl_dst=haddr_to_bin(dst))

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        
        eth = pkt.get_protocol(ethernet.ethernet)
        dst = eth.dst
        src = eth.src
        
        #self.logger.info("Packet type %s: %s", type(pkt), pkt)
        
        l4 = pkt.get_protocol(tcp.tcp)
        #self.logger.info("TCP type %s: %s", type(l4), l4)
        dstport = l4.dst_port if l4 else None
        
        l3 = pkt.get_protocol(ipv4.ipv4)
        #self.logger.info("IP type %s: %s", type(l3), l3)
        srcip = l3.src if l3 else None
        
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.in_port)
        self.logger.info("dstport = %s, srcip = %s", dstport, srcip)
        
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        if False:#dstport == 80 and srcip != '192.168.57.5':
            actions = [] #blank actions leads to dropping of packet
            self.logger.info("HTTP packet dropped")
        else:
            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
            self.logger.info("packet allowed out through %s", out_port)

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, msg.in_port, dst, actions)

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions)
        datapath.send_msg(out)

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
            
# :indentSize=4:tabSize=4:noTabs=true:wrap=soft: