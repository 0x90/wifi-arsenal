#!/usr/bin/env ruby
#
# HTTP Exploit Proxy/Server
#
# This module is the delivery mechanism for HTTP client-side
# exploits.  Most exploits require just file distribution and just
# register themselves as a virtual directory.  The exploits may also
# register notifications when certain files are retrieved in order to
# gauge progress or success.
# 
# Dino Dai Zovi <ddz@theta44.org>
#

require 'webrick'
require 'webrick/httpproxy'
require 'resolv-replace'    # to make sockets non-blocking

#
# Make WEBrick::HTTPRequest URIs mutable by adding this method to
# HTTPRequest objects at runtime.
#
module MutableHTTPRequest
    def update_uri(uri)
        @unparsed_uri = uri
        @request_uri = parse_uri(@unparsed_uri)
    end
end

class HttpServer
    def initialize(mod)
        @mod = mod
    end

    def run()
        address = @mod.requires['NETWORK-INTERFACE'].options['address']
        port = @mod.options['port'] or 80
        redirect = @mod.options['redirect'] or "/controller/"

        if (@mod.options['proxy'])
            @webrick = HttpProxyServer.new(address, port)
        else
            @webrick = WEBrick::HTTPServer.new(:Port => port,
                                               :BindAddress => address,
                                               :ServerType => Thread)
        end

        #
        # Mount a proc on root to direct any request to our "exploit
        # controller" servlet that gathers info from client and redirects
        # them to exploit servlets.
        #
        @webrick.mount_proc("/"){|req, res|
            #
            # XXX: Maybe use META-REDIRECT?
            #
            res.set_redirect(WEBrick::HTTPStatus::MovedPermanently, 
                             redirect)
        }

        @mod.options['webrick'] = @webrick

        @webrick.start()
    end

    def stop()
        @webrick.stop()
    end

    def run_module(mod)
        vpath = mod.options['virtual-path']
        rpath = mod.options['real-path']

        if (rpath[0] != '/')
            rpath = mod.path + "/" + rpath
        end

        @webrick.mount(vpath, WEBrick::HTTPServlet::FileHandler, rpath)
    end

    def stop_module(mod)
        @webrick.umount(mod.options['virtual-path'])
    end
end

class HttpProxyServer < WEBrick::HTTPProxyServer
    
    def initialize(address = "0.0.0.0", port = 80)
        super(:Port => port,
              :BindAddress => address,
              :ProxyVia => true,
              :ServerType => Thread);
    end
    
    def service(req, res)
        # Detect looping back into ourselves
        if req['via'] == @via
            raise WEBrick::HTTPStatus::NotFound
        else
            host = req["Host"]
            
            if (host && !(host =~ %r!karma!i) && 
                      !(req.unparsed_uri =~ %r!~http://!))
                req.extend MutableHTTPRequest
                req.update_uri("http://" + host + req.unparsed_uri)
            end
            
            super(req, res)
        end
    end
    
    def proxy_service(req, res)
        #
        # XXX: Test injection criteria here
        #
        
        super(req, res)
    end
    
    #
    # XXX: Method to add exploit injectors
    #

end

