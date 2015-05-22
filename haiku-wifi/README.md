# haiku wifi

haiku wifi is a neighborhood bulletin board, hosted on a router, living in the wireless cloud.

look for wireless networks to see the current haiku. connect to the haiku network to write a new haiku.

![screenshot](http://farm8.staticflickr.com/7148/6793325161_714bdb4849_o.png)

[More screenshots](http://www.flickr.com/photos/42137335@N07/sets/72157629093151189/) and [people writing poetry](http://www.flickr.com/photos/37234044@N07/sets/72157629094958315/)

## credits

haiku wifi was created by jonathan dahan and toby schachman at [art hack day 2012](http://arthackday.net) at [319 scholes](http://319scholes.org/).

special thanks to sean mcintyre for lending us a router and tons of assistance with configuration. thanks also to jonathan kiritharan for assistance and josh keay for design ideas.

## how it works

The commodity wifi router (we used a Netgear N600) runs the [Open-WRT](https://openwrt.org/) firmware, a linux distribution for embedded devices (like wireless routers). Essentially this gives us an open linux box with wifi routing capabilities.

With Open-WRT, you can create as many SSIDs as you want by simply changing the config file `/etc/confic/wireless` (the preferred way of doing this on Open-WRT is to use the included [uci](http://wiki.openwrt.org/doc/start#uci.configuration) utility). We made 3 placeholder SSIDs (named `-1 ...`, `-2 ...`, `-3 ...`) and 1 SSID which doesn't change named `-4 --- ☁ haiku wifi ☁ ---`. The 3 placeholder SSIDs will be renamed by the users.

We installed Python and [Flask](http://flask.pocoo.org/) on our router. This gives us a little web server to serve the web page form to change the haiku. Our Python web app makes command line calls to reconfigure our wireless config file and restart the wifi.

Finally, we changed the default admin interface to run on port 81 (instead of 80). We made an init script to run our Python web app on startup (on port 80). And we configured dnsmasq to forward all domains to 192.168.1.1, so that when a user went to any website they would see the haiku page.

## installation

1. Install [Open-WRT](https://openwrt.org/) on your router.

2. Install Python on your router.

        opkg install python

3. Install [setuptools](http://pypi.python.org/pypi/setuptools#cygwin-mac-os-x-linux-other).

4. Install [Flask](http://flask.pocoo.org/).

5. Configure your wireless interfaces to create 3 placeholders (the Python web server will be changing these) and (optionally) one that won't change. You can use `uci` or edit `/etc/config/wireless` directly. You'll want your `wifi-iface`s to be like the following:

        config 'wifi-iface'
          option 'device' 'radio0'
          option 'mode' 'ap'
          option 'encryption' 'none'
          option 'network' 'lan'
          option 'ssid' '-1 ...'

        config 'wifi-iface'
          option 'device' 'radio0'
          option 'mode' 'ap'
          option 'encryption' 'none'
          option 'network' 'lan'
          option 'ssid' '-2 ...'

        config 'wifi-iface'
          option 'device' 'radio0'
          option 'mode' 'ap'
          option 'encryption' 'none'
          option 'network' 'lan'
          option 'ssid' '-3 ...'

        config 'wifi-iface'
          option 'device' 'radio0'
          option 'mode' 'ap'
          option 'encryption' 'none'
          option 'network' 'lan'
          option 'ssid' '-4 --- ☁ haiku wifi ☁ ---'

    Note that the web app is expecting to reconfigure `wifi-iface` 0-2, so if you don't have these placeholders as the first `wifi-iface`s, change the `radio_offset` variable in the web app.

6. Make LuCI (the default web admin tool for Open-WRT) start up on port 81. In `/etc/config/uhttpd`, change this line

        list listen_http	0.0.0.0:80

    to

        list listen_http	0.0.0.0:81

7. Put the web app--this repository--on your router in `/root/arthackday`. (`git clone` it and then `scp` it to the router.)

8. Install the initscript to run the python web app when the router starts up:

        cp init.d/haiku /etc/init.d/haiku

    and enable it by running

        /etc/init.d/haiku-wifi enable

9. Configure dnsmasq to point all domains at 192.168.1.1. Append these lines to `/etc/dnsmasq.conf`:

        address=/apple.com/0.0.0.0
        address=/#/192.168.1.1

10. All set! Power cycle the router.
