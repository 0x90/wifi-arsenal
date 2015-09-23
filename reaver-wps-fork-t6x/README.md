# Overview

**Reaver** has been designed to be a robust and practical attack against **Wi-Fi Protected Setup (WPS)** registrar PINs in order to **recover WPA/WPA2 passphrases**. It has been tested against a wide variety of access points and WPS implementations.

The **original** Reaver implements a **online brute force attack** against, as described in [http://sviehb.files.wordpress.com/2011/12/viehboeck_wps.pdf](http://sviehb.files.wordpress.com/2011/12/viehboeck_wps.pdf).
**reaver-wps-fork-t6x** is a **community forked version**, which has included **various bug fixes** and additional attack method (the **offline Pixie Dust** attack).

**Depending on the target's Access Point (AP)**, to recover the plain text WPA/WPA2 passphrase the **average** amount of time for the transitional **online brute force** method is **between 4-10 hours**. In practice, it will generally take half this time to guess the correct WPS pin and recover the passphrase.
When using the **offline attack**, **if** the AP is vulnerable, it may take only a matter of **seconds to minutes**.

* The original Reaver (v1.4) can be found here: [https://code.google.com/p/reaver-wps/](https://code.google.com/p/reaver-wps/).
* The discontinued community edition of Reaver (v1.5) that was used as the starting point: [https://code.google.com/p/reaver-wps-fork/](https://code.google.com/p/reaver-wps-fork/).
* reaver-wps-fork-t6x community edition of Reaver (which includes the Pixie Dust attack): [https://github.com/t6x/reaver-wps-fork-t6x](https://github.com/t6x/reaver-wps-fork-t6x).
* For more information about the Pixie Dust attack (including **which APs are vulnerable**) can be found here: 			[https://github.com/wiire/pixiewps](https://github.com/wiire/pixiewps), 
[https://forums.kali.org/showthread.php?24286-WPS-Pixie-Dust-Attack-(Offline-WPS-Attack)](https://forums.kali.org/showthread.php?24286-WPS-Pixie-Dust-Attack-(Offline-WPS-Attack)) & 									[https://docs.google.com/spreadsheets/d/1tSlbqVQ59kGn8hgmwcPTHUECQ3o9YhXR91A_p7Nnj5Y/edit?usp=sharing](https://docs.google.com/spreadsheets/d/1tSlbqVQ59kGn8hgmwcPTHUECQ3o9YhXR91A_p7Nnj5Y/edit?usp=sharing)

- - -

# Requirements

```
apt-get -y install build-essential libpcap-dev sqlite3 libsqlite3-dev aircrack-ng pixiewps
```
_The example uses [Kali Linux](https://www.kali.org/) as the Operating System (OS) as `pixiewps` is included._

You **must** already have Wiire's Pixiewps installed.
The latest version can be found here: [https://github.com/wiire/pixiewps](https://github.com/wiire/pixiewps).

- - -

# Setup

**Download**

`git clone https://github.com/t6x/reaver-wps-fork-t6x`

or

`wget https://github.com/t6x/reaver-wps-fork-t6x/archive/master.zip && unzip master.zip`

**Build**

```bash
cd reaver-wps-fork-t6x*/
cd src/
./configure
make
```

**Install**

`sudo make install`

- - -

# Reaver Usage

```
Reaver v1.5.2 WiFi Protected Setup Attack Tool
Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>
mod by t6_x <t6_x@hotmail.com> & DataHead & Soxrok2212 & Wiire & kib0rg

Required Arguments:
		-i, --interface=<wlan>          Name of the monitor-mode interface to use
		-b, --bssid=<mac>               BSSID of the target AP

Optional Arguments:
		-m, --mac=<mac>                 MAC of the host system
		-e, --essid=<ssid>              ESSID of the target AP
		-c, --channel=<channel>         Set the 802.11 channel for the interface (implies -f)
		-o, --out-file=<file>           Send output to a log file [stdout]
		-s, --session=<file>            Restore a previous session file
		-C, --exec=<command>            Execute the supplied command upon successful pin recovery
		-D, --daemonize                 Daemonize reaver
		-a, --auto                      Auto detect the best advanced options for the target AP
		-f, --fixed                     Disable channel hopping
		-5, --5ghz                      Use 5GHz 802.11 channels
		-v, --verbose                   Display non-critical warnings (-vv for more)
		-q, --quiet                     Only display critical messages
		-K  --pixie-dust=<number>       [1] Run pixiewps with PKE, PKR, E-Hash1, E-Hash2, E-Nonce and Authkey (Ralink, Broadcom & Realtek)
		-Z, --no-auto-pass              Do NOT run reaver to auto retrieve WPA password if pixiewps attack is successful
		-h, --help                      Show help

Advanced Options:
		-p, --pin=<wps pin>             Use the specified 4 or 8 digit WPS pin
		-d, --delay=<seconds>           Set the delay between pin attempts [1]
		-l, --lock-delay=<seconds>      Set the time to wait if the AP locks WPS pin attempts [60]
		-g, --max-attempts=<num>        Quit after num pin attempts
		-x, --fail-wait=<seconds>       Set the time to sleep after 10 unexpected failures [0]
		-r, --recurring-delay=<x:y>     Sleep for y seconds every x pin attempts
		-t, --timeout=<seconds>         Set the receive timeout period [5]
		-T, --m57-timeout=<seconds>     Set the M5/M7 timeout period [0.20]
		-A, --no-associate              Do not associate with the AP (association must be done by another application)
		-N, --no-nacks                  Do not send NACK messages when out of order packets are received
		-S, --dh-small                  Use small DH keys to improve crack speed
		-L, --ignore-locks              Ignore locked state reported by the target AP
		-E, --eap-terminate             Terminate each WPS session with an EAP FAIL packet
		-n, --nack                      Target AP always sends a NACK [Auto]
		-w, --win7                      Mimic a Windows 7 registrar [False]
		-X, --exhaustive                Set exhaustive mode from the beginning of the session [False]
		-1, --p1-index                  Set initial array index for the first half of the pin [False]
		-2, --p2-index                  Set initial array index for the second half of the pin [False]
		-P, --pixiedust-loop            Set into PixieLoop mode (doesn't send M4, and loops through to M3) [False]
		-W, --generate-pin              Default Pin Generator by devttys0 team [1] Belkin [2] D-Link
		-H, --pixiedust-log             Enables logging of sequence completed PixieHashes

Example:
		reaver -i wlan0mon -b 00:AA:BB:11:22:33 -vvv -K 1
```

## -K // --pixie-dust

The `-K 1` option performances the offline attack, Pixie Dust _(`pixiewps`)_, by automatically passing the **PKE**, **PKR**, **E-Hash1**, **E-Hash2**, **E-Nonce** and **Authkey** variables. `pixiewps` will then try to attack **Ralink**, **Broadcom** and **Realtek** detected chipset.
**Special note**: If you are attacking a **Realtek AP**, **do NOT** use small DH Keys (`-S`) option.

## -H // --pixiedust-log

The `-H` option is a switch to enable logging of PixieHashes, **saved hashes** will be saved in the **executing directory**.
This option requires you to have at the least `-vvv` switch on and will work with `-K 1` & `-P` appropriately.

The files saved are named after the bssid (MAC) of the target, and with an extention of `.pixie`.
On the inside of these saved logs, you will find all the required **PixieDust hashes**, along with a **quick copy & paste ready full command** to use it on `pixiewps`. You also have the option to execute it. Just pop in the file into your favorite shell, and execute it _(`chmod +x <filename>` may be required)_.

## -P // --pixiedust-loop

When using the `-P` option, Reaver goes into a loop mode that breaks the WPS protocol by not using M4 message to **hopefully avoid lockouts**.
This is to **ONLY** be used for PixieHash collecting to use with `pixiewps`, **NOT** to brute forcing 'online' pins.

This option was made with intent of:

* Collecting repetitive hashes for further comparison and or analysis / **discovery of new vulnerable chipsets**, routers etc..
* **Time sensitive attacks** where the hash collecting continues repetitively until your time frame is met.
* For **scripting purposes** of whom want to use a possible lockout preventable way of PixieHash gathering for your use case.

- - -

# Wash Usage

```
Wash v1.5.2 WiFi Protected Setup Scan Tool
Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>
mod by t6_x <t6_x@hotmail.com> & DataHead & Soxrok2212 & Wiire & kib0rg

Required Arguments:
		-i, --interface=<iface>              Interface to capture packets on
		-f, --file [FILE1 FILE2 FILE3 ...]   Read packets from capture files

Optional Arguments:
		-c, --channel=<num>                  Channel to listen on [auto]
		-o, --out-file=<file>                Write data to file
		-n, --probes=<num>                   Maximum number of probes to send to each AP in scan mode [15]
		-D, --daemonize                      Daemonize wash
		-C, --ignore-fcs                     Ignore frame checksum errors
		-5, --5ghz                           Use 5GHz 802.11 channels
		-s, --scan                           Use scan mode
		-u, --survey                         Use survey mode [default]
		-P, --file-output-piped              Allows Wash output to be piped. Example. wash x|y|z...
		-g, --get-chipset                    Pipes output and runs reaver alongside to get chipset
		-h, --help                           Show help

Example:
		wash -i wlan0mon
```

## -g // --get-chipset

The option `-g` of Wash, automatically runs Reaver to receive the chipset data.
**If** the AP does not respond to them quickly, this option will be **slow to display the data**, because Reaver will stay running until getting the data or until you reach your timeout limit (30 seconds).

- - -

# Acknowledgements

## Contribution

Modifications made by:
`t6_x`, `DataHead`, `Soxrok2212`, `Wiire`, `kib0rg`

Some ideas made by:
`nuroo`, `kcdtv`

Bug fix made by:
`alxchk`, `flatr0ze`, `USUARIONUEVO`, `ldm314`

## Special Thanks

* `Soxrok2212` for all work done to help in the development of tools
* `Wiire` for developing Pixiewps
* `Craig Heffner` for creating Reaver and for the creation of default pin generators (D-Link, Belkin) - http://www.devttys0.com/
