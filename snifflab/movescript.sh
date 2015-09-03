#!/bin/bash

# Set these vars to the SSH details of your pcap collecting machine
DATE=$1
PCAPFILE=$2
SSHUSERNAME=$3
SSHHOSTNAME=$4
SSHPATH=$5

ssh $SSHUSERNAME@$SSHHOSTNAME "cd $SSHPATH; mkdir $DATE"
scp $2 $SSHUSERNAME@$SSHHOSTNAME:$SSHPATH/$DATE/
if [ "$?" = "0" ]; then
	echo "Backed up file $PCAPFILE to $SSHHOSTNAME:$SSHPATH/"$DATE"/"
	rm  $PCAPFILE
	exit 0
else
	echo "Cannot backup pcap file. SSH error"
	exit 1
fi