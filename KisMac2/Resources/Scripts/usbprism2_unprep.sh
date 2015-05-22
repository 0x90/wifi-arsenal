#!/bin/sh

/bin/sleep 2

echo "restarting USB drivers"

if [ -e "/System/Library/Extensions/Intersil Prism2.kext" ]; then
        /sbin/kextload "/System/Library/Extensions/Intersil Prism2.kext"
fi

#if [ -e "/System/Library/Extensions/IntersilBase.kext" ]; then
#        /sbin/kextload "/System/Library/Extensions/IntersilBase.kext"
#fi

if [ -e "/System/Library/Extensions/AeroPad.kext" ]; then
        /sbin/kextload "/System/Library/Extensions/AeroPad.kext"
fi

#if [ -e "/System/Library/StartupItems/PrismStartup" ]; then
    #/bin/sleep 2
    #/System/Library/StartupItems/PrismStartup/prismStatD /System/Library/StartupItems/PrismStartup/prismStatus.app
    #/System/Library/StartupItems/PrismStartup/prismStatus.app/Contents/MacOS/prismStatus -psn_0_1835009
#fi
 
