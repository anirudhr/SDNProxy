#!/usr/bin/python
#:indentSize=4:tabSize=4:noTabs=true:wrap=soft:
#http://www.decalage.info/python/cherryproxy

import cherryproxy
import sys, os
"""
The following attributes can be read and MODIFIED:
    self.req.headers: dictionary of HTTP headers, with lowercase names
    self.req.method: HTTP method, e.g. 'GET', 'POST', etc
    self.req.scheme: protocol from URL, e.g. 'http' or 'https'
    self.req.netloc: IP address or hostname of server, with optional
                     port, for example 'www.google.com' or '1.2.3.4:8000'
    self.req.path: path in URL, for example '/folder/index.html'
    self.req.query: query string, found after question mark in URL

The following attributes can be READ only:
    self.req.environ: dictionary of request attributes following WSGI
                      format (PEP 333)
    self.req.url: partial URL containing 'path?query'
    self.req.full_url: full URL containing 'scheme:netloc/path?query'
    self.req.length: length of request data in bytes, 0 if none
    self.req.content_type: content-type, for example 'text/html'
    self.req.charset: charset, for example 'UTF-8'
    self.req.url_filename: filename extracted from URL path
"""
class SDNProxy(cherryproxy.CherryProxy):
    def filter_request_headers(self):
        #self.log.debug(header location)
    if False:#self.req.full_url ##########Block check
        msg = "Request blocked"
        #self.log.warning(msg)
        self.set_response_forbidden(reason=msg)
    else:
        pass #SDN stuff here
    
    def filter_response_headers(self):
        pass
    
    def filter_response(self):
        pass
    
cherryproxy.main(SDNProxy)