#!/usr/bin/python
#:indentSize=4:tabSize=4:noTabs=true:wrap=soft:
#http://www.decalage.info/python/cherryproxy

import cherryproxy
import sys, os

with open('domain_blacklist') as f:
    blist = f.readlines()
    f.close()
blacklist = [x.rstrip() for x in blist]

class SDNProxy(cherryproxy.CherryProxy):
    def filter_request_headers(self):
        #self.log.debug(header location)
        if self.req.netloc in blacklist:
            msg = "Request to " + self.req.netloc + " blocked by blacklist policy"
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

cherryproxy.main(SDNProxy)