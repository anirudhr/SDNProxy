#!/usr/bin/python
#:indentSize=4:tabSize=4:noTabs=true:wrap=soft:
#http://www.decalage.info/python/cherryproxy
#http://osrg.github.io/ryu/

import cherryproxy
import logging
import struct

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
