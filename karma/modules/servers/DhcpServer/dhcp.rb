#!/usr/bin/env ruby
#
#
#

require 'tempfile.rb'

class DhcpServer
    
    def initialize(mod)
        @mod = mod
        @options = mod.options
    end

    def tmpnam()
        # XXX: This is a hack
        tf = Tempfile.new("karma");
        path = tf.path()
        tf.close
        return path
    end

    def inet_aton(addr)
        parts = addr.split(/\./)
        i = (parts[0].to_i() << 24) |
            (parts[1].to_i() << 16) |
            (parts[2].to_i() << 8)  |
            (parts[3].to_i())
        return i
    end

    def inet_ntoa(addr)
        a = (addr >> 24 & 0xff).to_s()
        b = (addr >> 16 & 0xff).to_s()
        c = (addr >> 8 & 0xff).to_s()
        d = (addr & 0xff).to_s()
        
        return a + "." + b + "." + c + "." + d
    end

    def run()
        @dhcpd = @options['dhcpd'] or
            raise "Need dhcpd option (path to dhcpd binary)"

        if (!File.executable?(@dhcpd))
	    raise "Dhcpd binary #{@dhcpd} not found"
	end

        #
        # Create dhcpd config file using option values
        #
        
        ni = @mod.requires['NETWORK-INTERFACE']
        
        @pid_file = tmpnam()
        File.delete(@pid_file)
        @config_file = tmpnam()
        @lease_file = tmpnam()

        address = ni.options['address']
        netmask = ni.options['netmask']
        netmask_n = inet_aton(netmask)

        subnet_n = inet_aton(address) & netmask_n
        subnet = inet_ntoa(subnet_n)
        dhcp_begin = inet_ntoa(subnet_n + 1)
        #
        # ISC dhcpd is stoopid and can't use a range that spans
        # a class C, even if the subnet is wider than that.
        #
        
        dhcp_end = inet_ntoa((subnet_n | (~netmask_n & 0xff)) - 1)

        File.open(@config_file, "w") {|io|
            io.print "pid-file-name \"#{@pid_file}\";\n"
            io.print "option domain-name-servers #{address};\n"
            io.print "ddns-update-style ad-hoc;\n"
            io.print "authoritative;\n\n"

            io.print "shared-network VICTIMS {\n"
            io.print "  subnet #{subnet} netmask #{netmask} {\n"
            io.print "    option routers #{address};\n"
            io.print "    option domain-name-servers #{address};\n"
            io.print "    range #{dhcp_begin} #{dhcp_end};\n"
            io.print "  }\n"
            io.print "}\n"
        }

        #
        # Run dhcpd parsing its output
        #
        if (@mod.options['port'])
            port = @mod.options['port']
        else
            port = 67
        end
        interface = ni.options['interface']
        dhcpd_cmd = @dhcpd + " -d -f"
        dhcpd_cmd += " -p " + port.to_s()
        dhcpd_cmd += " -cf " + @config_file 
        dhcpd_cmd += " -lf " + @lease_file 
        dhcpd_cmd += " " + interface
        dhcpd_cmd += " 2>&1"
        
        IO.popen(dhcpd_cmd) { |io|
            io.each() { |line|
                case line
                when /DHCPDISCOVER from ([0-9a-f:]{17})/
                    mac = $1

                    puts "DhcpServer: #{mac} discover"

                when /DHCPACK on ([0-9.]+) to ([0-9a-f:]{17}) \((.*)\)/
                    ip = $1
                    mac = $2
                    client_id = $3

                    puts "DhcpServer: #{mac} (#{client_id}) <- #{ip}"

                end
            }
        }
    end

    def stop()
        # Read pid out of our dhcpd pid file
        pid = File.open(@pid_file) { |io| io.readline() }.to_i()

        # kill daemon
        Process.kill("SIGHUP", pid)

        # remove temp files
        File.delete(@pid_file, @config_file, @lease_file, @lease_file + "~")

    end
    
end
