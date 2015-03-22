# Wifi-linux
Simple python script, which collects RSSI information about wifi access points around you and draws graphics showing RSSI activity.
##Usage
./list_rssi.py <tick tim (secs)> <Watched access point1> <Watch access point2> ....

After start you recieve an output of all access points around you.
After that you will be prompted for a command.
    plot
        draw an RSSI activity graphic for this moment since program start
    bp
        add a small breakpoint to a future graphic here
    stop
        stop the program
    start
        start timer and data processing
    start changer
        start data processing for every event on adapter
    print
        print rssi data
###Example
    ./list_rssi.py 5 WifiHome WifiBuddy Dlink200
    ...wait for some time
    bp
    added a breakpoint 
    ...wait for some time
    pl
    ...watch your graphic
    st
##Commit hist
    02.06.2011: First commit - a printed list [AP: RSSI]
    02.06.2011: Now refreshes on every signal change, completely new design
    02.06.2011: Gnuplot
    09.06.2011: New functionality - start changer, print.
