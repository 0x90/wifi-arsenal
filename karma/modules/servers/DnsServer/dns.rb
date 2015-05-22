#!/usr/bin/env ruby
#
#
#

#
# TODO:
# - record queries made by each host
# - use query characteristics for fingerprinting
# - allow DNS proxy mode (allow switch to rogue for chosen hosts)
#

require 'resolv'

#
# Simple DNS server to respond to every A? question with A <host>
#
class DnsServer
    def initialize(mod)
        @mod = mod
    end

    def run()
        # Retrieve IP address from NETWORK-INTERFACE
        @address = @mod.requires['NETWORK-INTERFACE'].options['address'] or
            raise "Require address option from NETWORK-INTERFACE"

        if (@mod.options['port'])
            @port = @mod.options['port']
        else
            @port = 53
        end

        # MacOS X workaround
        Socket.do_not_reverse_lookup = true
            
        @sock = UDPSocket.new()
        @sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
        @sock.bind(@address, @port)
        @run = true
        while @run
            packet, addr = @sock.recvfrom(65535)
            if (packet.length == 0)
                break
            end
            request = Resolv::DNS::Message.decode(packet)
            
            #
            # XXX: Track request IDs by requesting IP address and port
            #
            # Windows XP SP1a: UDP source port constant, 
            #  sequential IDs since boot time
            # Windows XP SP2: Randomized IDs
            #
            # Debian 3.1: Static source port (32906) until timeout, 
            #  randomized IDs
            #
            print "DNS: #{addr[3].to_s()}.#{addr[1].to_s()}: #{request.id.to_s()}"
            request.each_question {|name, typeclass|
                tc_s = typeclass.to_s().gsub(/^Resolv::DNS::Resource::/, "")
                
                print " #{tc_s} #{name}"
                if typeclass == Resolv::DNS::Resource::IN::A
                    
                    # Special fingerprinting name lookups:
                    #
                    # _isatap -> XP SP = 0
                    # isatap.localdomain -> XP SP >= 1
                    # teredo.ipv6.microsoft.com -> XP SP >= 2
                    #
                    # time.windows.com -> windows ???
                    # wpad.localdomain -> windows ???
                    #
                    # <hostname> SOA -> windows XP self hostname lookup
                    #
                    
                    request.qr = 1
                    request.ra = 1
                    answer = Resolv::DNS::Resource::IN::A.new(@address)
                    request.add_answer(name, 60, answer)
                end
            }
            print "\n"
            
            @sock.send(request.encode(), 0, addr[3], addr[1])
        end
        if (@run)
            @sock.close
            @run = false
        end
    end

    def stop()
        @run = false
    end
end
