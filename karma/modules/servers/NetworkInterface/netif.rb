#!/usr/bin/env ruby
#
#
#

class NetworkInterface
    #
    # We expect to be initialized with an active, running interface
    #
    def initialize(mod)
        @options = mod.options

        if not @options['ifconfig']
            raise "Need 'ifconfig' option (path to ifconfig)"
        end

        if not @options['interface'] 
            raise "Need 'interface' option (name of interface)"
        end

        #
        # These are both optional, if they are specified, we will
        # configure the network interface with them
        #
        if @options['address'] and @options['netmask']
            @configure = true  # we configure the interface
        else
            get_ip_and_mask()
        end

    end

    def run()
        # If address and netmask were provided, bring the interface up
        # with them
        if @configure
            ifconfig("up " + @options['address'] + 
                            " netmask " + @options['netmask'])
        end
    end

    def stop()
        # Take down interface only if we brought it up
        if @configure
            ifconfig("down 0.0.0.0")
        end
    end

    def ifconfig(command)
        cmd = @options['ifconfig'] + " " + @options['interface'] + " " + command
        system(cmd)
    end

    #
    # Retrieve IP address and netmask from ipconfig output
    # XXX: Linux specific 
    #
    def get_ip_and_mask()
        IO.popen(@options['ifconfig'] + " " + @options['interface']) {|io|
            io.each() { |line|
                case line
                when /\s*inet\saddr:([.\d]+).*Mask:([.\d]+)/
                    @options['address'] = $1
                    @options['netmask'] = $2
                end
            }
        }
    end
    
end
