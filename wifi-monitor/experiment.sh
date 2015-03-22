#!/bin/sh

date 010800002009

for a in 30
do
        echo "python rtt_measurement.py > /dev/null &"
	python rtt_measurement.py > /dev/null &

	echo "python /root/wifi-monitor/py_monitoring.py -t ${1} -m ${2} -x ${a}"
	python /root/wifi-monitor/py_monitoring.py -t ${1} -m ${2} -x ${a}
	mv 12*.csv ${a}.csv
done
