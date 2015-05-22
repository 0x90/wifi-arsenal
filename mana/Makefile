
all:
	$(MAKE) -C hostapd-manna/hostapd/

install:
	# Create the target directories
	install -d -m 755 $(DESTDIR)/usr/share/mana-toolkit/www
	install -d -m 755 $(DESTDIR)/usr/share/mana-toolkit/crackapd
	install -d -m 755 $(DESTDIR)/usr/share/mana-toolkit/firelamb
	install -d -m 755 $(DESTDIR)/usr/share/mana-toolkit/sslstrip-hsts/sslstrip
	install -d -m 755 $(DESTDIR)/usr/share/mana-toolkit/cert
	install -d -m 755 $(DESTDIR)/usr/share/mana-toolkit/run-mana
	install -d -m 755 $(DESTDIR)/usr/lib/mana-toolkit/
	install -d -m 755 $(DESTDIR)/var/lib/mana-toolkit/sslsplit
	install -d -m 755 $(DESTDIR)/etc/mana-toolkit/
	install -d -m 755 $(DESTDIR)/etc/stunnel/
	install -d -m 755 $(DESTDIR)/etc/apache2/sites-available/
	# Install configuration files
	install -m 644 run-mana/conf/* $(DESTDIR)/etc/mana-toolkit/
	install -m 644 crackapd/crackapd.conf $(DESTDIR)/etc/mana-toolkit/
	install -m 644 apache/etc/apache2/sites-available/* $(DESTDIR)/etc/apache2/sites-available/
	# Install the stunnel configuration we want
	install -m 644 apache/etc/stunnel/stunnel.conf $(DESTDIR)/etc/stunnel/mana-toolkit.conf
	# Install the hostapd binary
	install -m 755 hostapd-manna/hostapd/hostapd $(DESTDIR)/usr/lib/mana-toolkit/
	install -m 755 hostapd-manna/hostapd/hostapd_cli $(DESTDIR)/usr/lib/mana-toolkit/
	# Install the data
	cp -R apache/var/www/* $(DESTDIR)/usr/share/mana-toolkit/www/
	install -m 644 run-mana/cert/* $(DESTDIR)/usr/share/mana-toolkit/cert/
	# Install the scripts
	install -m 755 crackapd/crackapd.py $(DESTDIR)/usr/share/mana-toolkit/crackapd/
	install -m 644 firelamb/* $(DESTDIR)/usr/share/mana-toolkit/firelamb/
	chmod 755 $(DESTDIR)/usr/share/mana-toolkit/firelamb/*.py \
	          $(DESTDIR)/usr/share/mana-toolkit/firelamb/*.sh
	install -m 644 sslstrip-hsts/sslstrip/* \
	    $(DESTDIR)/usr/share/mana-toolkit/sslstrip-hsts/sslstrip/
	install -m 644 $$(find sslstrip-hsts/ -maxdepth 1 -type f) \
	    $(DESTDIR)/usr/share/mana-toolkit/sslstrip-hsts/
	chmod 755 $(DESTDIR)/usr/share/mana-toolkit/sslstrip-hsts/sslstrip.py \
	          $(DESTDIR)/usr/share/mana-toolkit/sslstrip-hsts/dns2proxy.py
	install -m 755 run-mana/*.sh $(DESTDIR)/usr/share/mana-toolkit/run-mana
	# Dynamic configuration (if not fake install)
	if [ "$(DESTDIR)" = "" ]; then \
	    if [ -e /etc/default/stunnel4 ]; then \
	        sed -i -e 's/^ENABLED=.*/ENABLED=1/' /etc/default/stunnel4; \
	    fi; \
	    a2enmod rewrite || true; \
	    for conf in apache/etc/apache2/sites-available/*; do \
	        a2ensite `basename $$conf` || true; \
	    done; \
	fi
