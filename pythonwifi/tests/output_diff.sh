#!/bin/bash
#
# output_diff.sh - generate a meld for the output of the
#                  C and Python versions of example code
#
# Copyright 2009 by Sean Robinson <seankrobinson@gmail.com>
#
# This file is part of Python WiFi
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

PYTHONWIFIBASEDIR=/home/sean/devel/python-wifi.dev

case "$1" in
'iwlist')
    IWCOMMAND=iwlist
    PYCOMMAND=$PYTHONWIFIBASEDIR/examples/iwlist.py
    ;;
'iwconfig')
    IWCOMMAND=iwconfig
    PYCOMMAND=$PYTHONWIFIBASEDIR/examples/iwconfig.py
    ;;
*)
    echo "Usage: output_diff.sh COMMAND INTERFACE SUBCOMMAND"
    echo "         COMMAND is iwlist or iwconfig"
    echo "         INTERFACE is the interface to use or - for none"
    echo "         SUBCOMMAND is the COMMAND's parameter to use (e.g. scan for iwlist)"
    echo
    echo "         (ex: output_diff.sh iwlist wlan0 channel)"
    exit 1
    ;;
esac

# if user passes hyphen for 2nd param, use no interface in command call
if [ "$2" == "-" ]; then
    NIC=""
else
    NIC=$2
fi

# if user passes hyphen for 3rd param, use no subcommand in command call
if [ "$3" == "-" ]; then
    SUBCOMMAND=""
else
    SUBCOMMAND=$3
fi

# create some temporary files to hold each programs output
TMPFILE1=`mktemp -t diff-1-XXXXXX`
TMPFILE2=`mktemp -t diff-2-XXXXXX`

# remove the first three command line parameters
shift
shift
shift

# run commands and redirect output to temporary files
$IWCOMMAND $NIC $SUBCOMMAND $@ > $TMPFILE1 2>&1
$PYCOMMAND $NIC $SUBCOMMAND $@ > $TMPFILE2 2>&1

# call meld to compare files
meld -L $IWCOMMAND $TMPFILE1 -L $PYCOMMAND $TMPFILE2

# remove the temporary files
rm $TMPFILE1 $TMPFILE2

