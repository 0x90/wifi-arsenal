#!/bin/bash
#lets check if everything is working fine

function checkInstallation {
	if [ "$(which $1)" != "" ]
	then 
		echo "$1 installation: OK"
	else
		echo "$1 installation: FAILED"
	fi
}

checkInstallation automake
checkInstallation autoconf
checkInstallation screen
checkInstallation python2.5
checkInstallation pyrit
checkInstallation cowpatty
checkInstallation crunch