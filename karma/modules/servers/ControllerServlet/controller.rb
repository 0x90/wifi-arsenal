#!/usr/bin/env ruby
#
#
#

class ControllerServlet
    
    def initialize(mod)
        @mod = mod
        @clients = Hash.new()
        @exploits = []
    end

    def run()
        if (@mod.options['path'])
            @path = @mod.options['path']
        else
            @path = "/controller"
        end

        @webrick = @mod.requires['HTTP-SERVER'].options['webrick']
        @webrick.mount_proc(@path) { |req, res|
            # real closures -- take that python!
            handle_request(req, res)
        }
    end

    def stop()
        @webrick.umount(@path)
    end

    def run_module(mod)
        vpath = mod.options['virtual-path']
        rpath = mod.options['real-path']

        if (rpath[0] != '/')
            rpath = mod.path + "/" + rpath
        end

        @webrick.mount(vpath, WEBrick::HTTPServlet::FileHandler, rpath)

        @exploits.push(vpath)
    end

    def stop_module(mod)
        @webrick.umount(mod.options['virtual-path'])
    end

    def handle_request(req, res)

        # Map IP -> client tracking object
        
        ip = req.peeraddr[3]

        if (@clients[ip])
            client = @clients[ip]
        else
            client = Client.new(ip, req['USER-AGENT'])
        end

        #
        # Iterate through web exploits to guide them to the next applicable
        # exploit
        #

        @exploits.each {|x|
            if not client.attempted_exploits.member?(x)
                client.attempted_exploits.push(x)
                res.set_redirect(WEBrick::HTTPStatus::MovedPermanently, x)
                break
            end
        }

    end

end

class Client
    attr_accessor :attempted_exploits

    def initialize(ip, user_agent)
        @ip = ip
        @userAgent = user_agent
        @attempted_exploits = []
    end

    def parseUserAgent()
        #
        # G-H-E-T-T-O
        #
        
        #
        # Try and match the browser
        #
        case @userAgent
        when /Firefox\/([\.\d]+)/
            @browser = ["FIREFOX", $1]

        when /Safari\/([\.\d]+)/
            @browser = ["SAFARI", $1]

        when /MSIE\ ([\.\d]+)/
            @browser = ["MSIE", $1]

        when /Opera\ ([\.\d]+)/
            @browser = ["OPERA", $1]

        when /Konqueror\/([\.\d]+)/
            @browser = ["KONQUEROR", $1]
            
        else
            @browser = ["UNKNOWN", "?.?.?"]

        end

        #
        # Try and match the operating system and arch
        #

        case @userAgent
        when /Linux/
            @os = ["LINUX", "?.?.?"]

        when /Linux\ i686/
            @os = ["LINUX", "?.?.?"]
            @arch = "X86"

        when /Windows\ NT\ ([\.\d]+)/
            @os = ["WINNT", $1]

        when /Windows\ 98/
            @os = ["WIN9X", "3"]
            @arch = "X86"

        when /Windows\ 95/
            @os = ["WIN9X", "2"]
            @arch = "X86"

        when /Win\ 9x\ 4.90/    # Windows ME
            @os = ["WIN9X", "4.90"]
            @arch = "X86"

        when /PPC\ Mac\ OS\ X/
            @os = ["MACOSX", "10.?.?"]
            @arch = "PPC"

        else
            @os = ["UNKNOWN", "?.?.?"]
            @arch = "???"
        end
    end
    

end
