Pyrit
+++++

A GPGPU-driven WPA/WPA2-PSK key cracker

Pyrit exploits the computational power of many-core- and GPGPU-platforms to
create massive databases, pre-computing part of the WPA/WPA2-PSK authentication
phase in a space-time tradeoff. 
It is a powerful attack against one of the world's most used security-protocols

http://code.google.com/p/pyrit/



Requirements
++++++++++++

Pyrit compiles and runs on Linux, FreeBSD and MacOS. Windows is not (and
probably never will be) supported; there are however some reports of successful
installations on Windows with the help of MinGW.

A couple of libraries and headers are required to build Pyrit:

  * Python >=2.5 and it's headers
    http://www.python.org
  * The OpenSSL library and headers
    http://www.openssl.org
  * The Pcap library and it's headers
    http://www.tcpdump.org
  * Scapy >=2.x (optional/runtime)
    http://www.secdev.org/projects/scapy/
  * SQLAlchemy >=0.5 (optional/runtime)
    http://www.sqlalchemy.org

Linux users running a binary distribution may need to install the development
packages for Python (e.g. python-devel), OpenSSL (e.g. openssl-devel or
libssl-dev) and libpcap (e.g. libpcap-devel). You also need a C-compiler
like gcc. Users of MacOS probably only need to have Xcode installed.



Installing
++++++++++

Unpack the source-code into a new directory like this:

    tar xvzf pyrit-0.4.0.tar.gz


Switch to the main module's directory. We use Python's distutils to compile and
install the code:

    cd pyrit-0.4.0
    python setup.py build


If everything went well and no errors are thrown at you, use distutils again to
install Pyrit:

    sudo python setup.py install


You can now execute 'pyrit' from your commandline; leave the source-code's
directory before doing so to prevent Python from getting confused with
module-lookups.



Reporting bugs / Getting help
+++++++++++++++++++++++++++++

Please take a look at the Troubleshooting-page in Pyrit's Wiki if you have
problems compiling or running Pyrit:

    http://code.google.com/p/pyrit/wiki/Troubleshooting
    
    
Please report bugs, glitches and enhancement proposals using Pyrit's issue-
tracker:
    
    http://code.google.com/p/pyrit/issues/list



License
+++++++

Pyrit is free software - free as in freedom. Everyone can inspect, copy or
modify it and share derived work under the GNU General Public License v3.
You should have received a copy of the GNU General Public License along with
Pyrit. If not, see <http://www.gnu.org/licenses/>.

Pyrit comes with a set of test-files:
 * "wpapsk-linksys.dump.gz" and "wpa2psk-linksys.dump.gz" from Cowpatty with
   permission from Joshua Wright (http://www.willhackforsushi.com).
 * "wpa2psk-MOM1.dump.gz" from Pyrit issue #120 with permission from the
   original owner (http://code.google.com/p/pyrit/issues/detail?id=120).
 * "wpa2psk-2WIRE972.dump.gz" from Pyrit issue #111 with permission from the
   original owner (http://code.google.com/p/pyrit/issues/detail?id=111)
 * "wpapsk-virgin_broadband.dump.gz" from Aircrack-ng ticket #721 with
   permission from the original owner (http://trac.aircrack-ng.org/ticket/721).
 * "wpa2psk-Red_Apple.dump.gz" from Aircrack-ng ticket #491 with permission
   from the original owner (http://trac.aircrack-ng.org/ticket/491).
