NOW=$(date +"%F_%H_%M_%S")
LOGFILE="log-$NOW.txt"
dmesg > ./logs/$LOGFILE
subl ./logs/$LOGFILE