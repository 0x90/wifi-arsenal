##### BrcmPatchRAM on Apple Mac

The instructions in the readme are for a [Hackintosh](http://en.wikipedia.org/wiki/OSx86), a normal PC modified to run Mac OS X.

You should __not__ follow the original instructions on a real Mac as it might inadvertently break things.

BrcmPatchRAM.kext is an unsigned kernel extension.

In order to use it unsigned kernel extensions need to be enabled.
Take the following steps in the Terminal:

 * Retrieve the current system boot arguments:
 
  ```
  sudo nvram boot-args
  ```  
   
 * Append "kext-dev-mode=1" to the boot-args:
 
  If for example boot-args was empty before:
  ```
  sudo nvram boot-args="kext-dev-mode=1"
  ```  
 * Reboot the Mac   

Next install BrcmPatchRAM.kext inside /System/Library/Extensions.
```
sudo cp -R ~/Downloads/BrcmPatchRAM.kext /System/Library/Extensions
touch /System/Library/Extensions
```

Wait about a minute before rebooting the Mac again.

If all works properly the firmware version in the Bluetooth profiler will now show a higher version than v4096 (4096 means its non-upgraded).

Additionally its possible to confirm BrcmPatchRAM did its job by executing the following in the terminal:
```
sudo cat /var/log/system.log | grep -i brcm[fp]
```

This will show a log excerpt of BrcmPatchRAM output during startup.
