# ath9k-4W-patch
Tutorial for increasing power of ath9k devices, such as TP-link WN722N, tested on Debian 8

# Instructions
## Kernel
1. Obtain kernel sources: `sudo aptitude install linux-source` or download a tarball from kernel.org (in which case you won't likely be able to directly apply these instructions, however)
2. Install dev tools: `sudo aptitude install build-essential dpkg-dev xz-utils libncurses5-dev`
3. Extract the files: `tar xJvf /usr/src/linux-source-3.16.tar.xz && cd linux-source-3.16`
4. Bring over your existing kernel configuration: `cp /boot/config-3.16.0-4-amd64 .config`
5. "Fix" the ath9k driver: after obtaining the Linux-3.16.7.patch from here, run `patch -p1 < Linux-3.16.7.patch`
6. Configure kernel as desired: `make menuconfig`
7. Compile: `make deb-pkg`
8. Go up one folder and copy/move the resulting packages

## Wireless-regdb
1. Install dev tools: `sudo apt-get build-dep wireless-regdb`
2. Obtain sources: `apt-get source wireless-regdb`
3. Enter source directory.
4. Generate signing key: `make ~/.wireless-regdb-YOURUSERNAMEHERE.key.priv.pem`
5. Select personal key: `nano debian/rules`, remove "export REGDB_AUTHOR  = benh@debian.org"
6. Remove precompiled database: `make maintainer-clean`
7. Replace database (db.txt) with the one supplied
8. `make && dpkg-buildpackage -us -uc`
9. Go up one folder and copy/move the resulting package

## CRDA
1. Install dev tools: `sudo apt-get build-dep crda`
2. Obtain sources: `apt-get source crda`
3. Enter source directory.
4. Copy over your public key, USERNAME.key.pub.pem, from wireless-regdb's source directory to the "pubkey" folder inside crda's source
5. `make && dpkg-buildpackage -us -uc`
6. Go up one folder and copy/move the resulting package

Finally, install all these packages and reboot to use the new kernel.

Good luck!

