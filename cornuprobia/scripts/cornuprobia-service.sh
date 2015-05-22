#!/bin/sh
### BEGIN INIT INFO
# Provides:          cornuprobia
# Required-Start:    $remote_fs $syslog
# Required-Stop:     $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Cornuprobia
# Description:       Cornuprobia - Fountain of 802.11 Probe Requests 
### END INIT INFO

# Author: Anders Sundman <anders@4zm.org>

case "$1" in
    start)
        echo "[+] Creating monitor mode interface"
        /home/pi/cornuprobia/scripts/mkif.sh
        echo "[+] Starting Cornuprobia"
        /usr/bin/python /home/pi/cornuprobia/cornuprobia.py -d -w /home/pi/cornuprobia/1984.wl mon0
        ;;
    stop)
        echo "[+] Stopping Cornuprobia"
        pkill -f cornuprobia.py
        echo "[+] Removing monitor mode interface"
        /home/pi/cornuprobia/scripts/rmif.sh
        ;;
    *)
        echo "Usage: /etc/init.d/cornuprobia-service.sh start|stop"
        exit 1
        ;;
esac

exit 0
