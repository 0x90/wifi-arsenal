#!/usr/bin/env ruby
#
#
#

#
# TODO:
# - Subclass out config for Linux+MadWifi, Linux+HostAP, FreeBSD, etc.
# - remember previous configuration and revert to it in stop()
#

class AccessPoint
    
    def initialize(mod)
        @options = mod.options
    end

    def run()
        ifconfig("down")

        #
        # Assign a random MAC address (Good idea, sigtrap)
        #
        rand_mac = sprintf("00:0%x:%.2x:%.2x:%.2x:%.2x",
                           rand(16), rand(256), rand(256),
                           rand(256), rand(256))
        ifconfig_options = " hw ether " + rand_mac
        ifconfig(ifconfig_options)

        if (@options['cloaked'] == "true")
            iwpriv("hide_ssid 1")
        end

        case (@options['auth'])
        when /open/
            iwpriv('authmode 1')
        when /shared/
            iwpriv('authmode 2')
        end

        case (@options['radiomode'])
        when /auto/
            iwpriv("mode 0")
        when /g/
            iwpriv("mode 3")
        when /b/
            iwpriv("mode 2")
        when /a/
            iwpriv("mode 1")
        end
            
        iwconfig_options = "mode Master"
        iwconfig_options += " nickname \"\""
        iwconfig_options += " essid \"" + @options['ssid'] + "\""
        iwconfig_options += " channel " + @options['channel']
        iwconfig(iwconfig_options)

        ifconfig_options = ""
        ifconfig_options += " inet " + @options['address']
        ifconfig_options += " netmask " + @options['netmask']
        ifconfig(ifconfig_options)
        ifconfig("up")

        #
        # Yeah, this is ghetto.  Parse iwevent output to get
        # notifications of stations joining/leaving network.
        #
        @iwevent_thread = Thread.new() {
            iwevent = @options['iwevent']
            IO.popen(iwevent + " 2>&1") { |io|
                io.each() { |line|
                    case line
                    when /Expired node:([0-9A-F:]{17})/
                        mac = $1
                        puts "AccessPoint: #{mac} disassociated\n"
                    end
                }
            }
        }

        @messages_thread = Thread.new() {
            messages = "/usr/bin/tail -f " + @options['messages']
            IO.popen(messages + " 2>&1") { |io|
                io.each() { |line|
                    case line
                    when /KARMA:.*\[(.*)\].*\["(.*)"\]/
			mac = $1
			ssid = $2
			puts "AccessPoint: #{mac} associated with SSID #{ssid}\n"
                    end
                }
            }
        }

    end

    def stop()
        @iwevent_thread.kill()

        ifconfig("inet 0.0.0.0")
        ifconfig("down")
        iwconfig("mode Managed")
    end

    def ifconfig(options)
        cmd = @options['ifconfig'] + " " + @options['interface'] + " " + 
              options
        system(cmd)
    end

    def iwconfig(options)
        cmd = @options['iwconfig'] + " " + @options['interface'] + " " + 
              options
        system(cmd)
    end

    def iwpriv(options)
        cmd = @options['iwpriv'] + " " + @options['interface'] + " " + 
              options
        system(cmd)
    end

end
