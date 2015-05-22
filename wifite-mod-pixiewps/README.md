#Added flags
    -pto <sec>        # configurable timeout for pixiewps attack, default 660
    -ponly            # uses only pixiewps and reaver up until M3
    -pnopsk           # do not run retrieved pin through reaver
    -paddto <sec>     # add n seconds to timeout on each hash retrevial, default 30
    -update           # now updates to this fork instead of original wifite
    -endless          # will now loop through targets forever until stopped
#Required tools

    You must install Pixiewps by Wiire (https://github.com/wiire/pixiewps)
      and 
    You must install reaver-wps-fork-t6x by t6x (https://github.com/t6x/reaver-wps-fork-t6x)

#ToDo
    Add check to see if update is needed before performing.
    Add option to dynamically spoof connected client
    Add option to auto-skip previously cracked AP instead of prompting

#May do    
    
    Add mdk3 support
    Add default pin calculations and options

