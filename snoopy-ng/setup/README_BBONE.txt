
BeagleBone Setup:

1. Install base Ubuntu Image on an SD card:
wget http://s3.armhf.com/debian/precise/bone/ubuntu-precise-12.04.2-armhf-3.8.13-bone20.img.xz
xz -cd ubuntu-precise-12.04.2-armhf-3.8.13-bone20.img.xz > /dev/sd_YOUR_SD_CARD

2. Insert SD card to device, SSH in (ubuntu:ubuntu), and place files in this folder:
/home/ubuntu/snoopy_ng/

If you wish to put them elsewhere, make sure you edit ./setup/upstarts/*.conf to relfect
the new location of ./setup/upstarts/SETTINGS

3. Go through INSTALL.sh. I'd recommend manually running these commands to watch out for errors. 

4. Copy the autostart scripts:
cp /home/ubuntu/snoopy_ng/setup/upstarts/*.conf /etc/init/

