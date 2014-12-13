#!/usr/bin/python
#:indentSize=4:tabSize=4:noTabs=true:wrap=soft:
#http://www.decalage.info/python/cherryproxy
#http://osrg.github.io/ryu/

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
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

class SDNProxy(cherryproxy.CherryProxy):
    def getBlacklist(self, filename='domain_blacklist'):
        with open(filename) as f:
            blist = f.readlines()
            f.close()
        blacklist = [x.rstrip() for x in blist]
        return blacklist
    def filter_request_headers(self):
        #self.log.debug(header location)
        self.blacklist = self.getBlacklist()
        if self.req.netloc in self.blacklist:
            msg = "Request to " + self.req.netloc + " blocked by self.blacklist policy"
            self.req.log.warning(msg)
            self.set_response_forbidden(reason=msg)
        else:
            msg = "Request to " + self.req.netloc + " passed."
            self.req.log.info(msg)
            #SDN stuff here
    
    def filter_response_headers(self):
        pass
    
    def filter_response(self):
        pass

############main
cherryproxy.main(SDNProxy)
