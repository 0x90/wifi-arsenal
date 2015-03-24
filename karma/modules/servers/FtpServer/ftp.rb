#!/usr/bin/env ruby
#
#
#

require 'gserver'

class FtpServer
    def initialize(mod)
        @mod = mod
    end

    def run()
        @address = @mod.requires['NETWORK-INTERFACE'].options['address'] or
            raise "Require address option from NETWORK-INTERFACE"

        if (@mod.options['port'])
            @port = @mod.options['port']
        else
            @port = 21
        end

        @pop3 = GFtpServer.new(@address, @port)
        @pop3.start()

    end

    def stop()
        @pop3.stop()
    end
end

class GFtpServer < GServer
    def initialize(address = "0.0.0.0", port = 110)
        super(port, address)
    end
    
    def serve(io)
        ip = io.peeraddr[3]
        user = ""
        pass = ""
        
        io.print "220 Welcome\r\n"
        
        while ((line = io.gets().chomp()))
            case line
            when /quit/i
                io.print "221 Logout.\r\n"
                break
                
            when /user\s(.*)/i
                user = $1
                io.print "331 User name okay, need password...\r\n"
                
            when /pass\s(.*)/i
                pass = $1
                
                puts "FTP: #{ip} #{user}/#{pass}"
                
                io.print "500 Error\r\n"
                
            else
                io.print "500 Error\r\n"
            end
        end
    end
end

