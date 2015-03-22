#!/bin/sh

#/usr/bin/killall prismStatus
#/usr/bin/killall prismStatD

/bin/sleep 1

if [ -e "/System/Library/Extensions/Intersil Prism2.kext" ]; then
    if /usr/sbin/kextstat -b com.Intersil.prism2 | /usr/bin/grep --quiet com.Intersil.prism2 ; then
        "/sbin/kextunload" "/System/Library/Extensions/Intersil Prism2.kext"
    fi
fi

if [ -e "/System/Library/Extensions/IntersilBase.kext" ]; then
    if /usr/sbin/kextstat -b com.Intersil.base | /usr/bin/grep --quiet com.Intersil.base ; then
        "/sbin/kextunload" "/System/Library/Extensions/IntersilBase.kext"
    fi
fi

if [ -e "/System/Library/Extensions/AeroPad.kext" ]; then
    if /usr/sbin/kextstat -b com.macsense.driver.AeroPad | /usr/bin/grep --quiet com.macsense.driver.AeroPad ; then
        "/sbin/kextunload" "/System/Library/Extensions/AeroPad.kext"
    fi
fi

/bin/sleep 1
