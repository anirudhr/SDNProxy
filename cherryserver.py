#!/usr/bin/python
#:indentSize=4:tabSize=4:noTabs=true:wrap=soft:
#http://www.decalage.info/python/cherryproxy
#http://osrg.github.io/ryu/

import cherryproxy
import logging
import struct
#import xmlrpclib

class SDNProxy(cherryproxy.CherryProxy):
    def markRequest(self, client_ip, CONNFILE = 'request_list'):
        try:
            with open(CONNFILE) as f:
                contents = f.read()
                f.close()
        except IOError as e:
            if e.errno == 2 and e.strerror == 'No such file or directory':
                contents = ''
            else:
                print 'Terrible error, cannot recover, bye'
                exit()
        if not client_ip in contents:
            with open(CONNFILE, 'a') as f:
                f.write(client_ip + '\n')
                f.close()
    def __init__(self, *args, **kwargs):
        super(SDNProxy, self).__init__(*args, **kwargs)
        with open('domain_blacklist') as f:
            blist = f.readlines()
            f.close()
        self.blacklist = [x.rstrip() for x in blist]
        #self.switch = xmlrpclib.ServerProxy("http://localhost:8000/")
    def filter_request_headers(self):
        #self.log.debug(header location)
        if self.req.netloc in self.blacklist:
            msg = "Request to " + self.req.netloc + " blocked by self.blacklist policy"
            self.req.log.warning(msg)
            self.set_response_forbidden(reason=msg)
        else:
            msg = "Request to " + self.req.netloc + " passed."
            self.req.log.info(msg)
            self.markRequest('192.168.57.5') #self.switch.authorize('192.168.57.5') #When we find a way to get the client IP, we will authorize it instead and pass a 302 back to the client to tell it to directly connect
    
    def filter_response_headers(self):
        pass
    
    def filter_response(self):
        pass

############main
cherryproxy.main(SDNProxy)
