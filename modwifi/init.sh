#!/bin/bash
trap "killall background" EXIT
git clone -b master   git@github.com:vanhoefm/modwifi.git           modwifi   &
git clone -b research git@github.com:vanhoefm/modwifi-linux.git     linux     &
git clone -b research git@github.com:vanhoefm/modwifi-ath9k-htc.git ath9k-htc &
git clone -b research git@github.com:vanhoefm/modwifi-backports.git backports &
git clone -b master   git@github.com:vanhoefm/modwifi-tools.git     tools     &
wait
