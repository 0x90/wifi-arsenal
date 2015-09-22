#!/bin/bash

DEST=${1:-}
HOST_STA=min-sta
HOST_AP=min-ap
HOSTS=("$HOST_AP" "$HOST_STA")

if [ -z "${DEST}" ]; then
	echo "no trace directory specified"
	exit 1
fi


if [ ! -d "${DEST}" ]; then
	mkdir "${DEST}" 2>/dev/null
fi

cp "logs/$TRACE.log" "${DEST}" 2>/dev/null

for h in "${HOSTS[@]}"
do
	echo "copying traces from ${h} ... "
	mkdir "${DEST}/$h" 2>/dev/null
	scp -r root@${h}:/tmp/traces/* "${DEST}/${h}/"
	if [ $? -eq 0 ]; then
		ssh root@${h} "rm -rf /tmp/traces/*"
		echo "deleted traces from ${h}"
	else
		echo "Error: copying from ${h} failed"
	fi
done

echo "done."
