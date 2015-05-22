ath9k-nav
=========

Tiny debugging aid to read the current value of an ath9k register. Currently set to read the [NAV](https://en.wikipedia.org/wiki/Network_allocation_vector) timer, which controls the device's MAC layer.

This was part of a project to artificially manipulate station's NAVs using [RTS/CTS](https://en.wikipedia.org/wiki/IEEE_802.11_RTS/CTS) mechanisms. It may be of further use as an example.

Originally built against linux-ath9kdebug-3.11.6-1-x86_64.pkg.tar.xz
