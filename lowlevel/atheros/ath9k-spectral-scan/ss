#!/bin/sh
max_samples=15000
plot_pause=0.05

# The function gathers the binary spectral scan data and outputs it.
# Each packet looks like this:
#   <number>\n
#   <base64 line 1>\n
#   <base64 line ..>\n
#   .\n
spectral_scan() {
	cat << 'EOF' | ssh steve sh

ifconfig wlan1 up

while true
do
	for i in $(seq 1 100)
	do
		echo $i
		echo chanscan \
			| tee /sys/kernel/debug/ieee80211/phy*/ath9k/spectral_scan_ctl \
			>/dev/null
		iw wlan1 scan chan-time 5 >/dev/null
		cat /sys/kernel/debug/ieee80211/phy*/ath9k/spectral_scan0 | base64
		echo .
	done
done

EOF
}

# The function processes spectral_scan() data into human readable output and puts it into /tmp/fft.dump.all.
# Each time new data arrives it is appended and the oldest data is pruned regularly.
# The output file is intended to be read by gnupot.
process() {
	while read i
	do
		echo $i
		while read line
		do
			test "$line" = . && break
			echo "$line"
		done | base64 -d > /tmp/fft.dump.$i

		cat /tmp/fft.dump.all > /tmp/fft.dump.all.new
		fft2txt < /tmp/fft.dump.$i | awk '{print $4 " " $6}' >> /tmp/fft.dump.all.new
		tail -n $max_samples < /tmp/fft.dump.all.new > /tmp/fft.dump.all.new.limited
		mv /tmp/fft.dump.all.new.limited /tmp/fft.dump.all

		# `mv` guarantees /tmp/fft.dump.all stays consistent
	done
}

# Essential gnuplot real-time drawing config
cat << EOF > /tmp/gnuplot.conf
set terminal wxt noraise
set yrange [-128:0]
pause $plot_pause
replot
reread
EOF

gnuplot=
trap '
	s=$?
	trap - EXIT QUIT
	kill -HUP $gnuplot
	exit $s
' INT HUP KILL TERM EXIT QUIT

touch /tmp/fft.dump.all
gnuplot -persistent -e 'plot "/tmp/fft.dump.all"' /tmp/gnuplot.conf & gnuplot=$!
spectral_scan | process
