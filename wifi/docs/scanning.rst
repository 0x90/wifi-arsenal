Managing WiFi networks
======================

.. currentmodule:: wifi

Discovering networks
--------------------

You can use this library to scan for networks that are available in the air.
To get a list of the different cells in the area, you can do ::

    >>> from wifi import Cell, Scheme
    >>> Cell.all('wlan0')

This returns a list of :class:`Cell` objects.  Under the hood, this calls `iwlist scan` and parses the unfriendly output.

Each cell object should have the following attributes:

- :attr:`ssid`
- :attr:`signal`
- :attr:`quality`
- :attr:`frequency`
- :attr:`bitrates`
- :attr:`encrypted`
- :attr:`channel`
- :attr:`address`
- :attr:`mode`

For cells that have :attr:`encrypted` as `True`, there will also be the following attributes:

- :attr:`encryption_type`

.. note::

    Scanning requires root permission to see all the networks.
    If you are not root, iwlist only returns the network you are currently connected to.


Connecting to a network
-----------------------

In order to connect to a network, you need to set up a scheme for it. ::

    >>> cell = Cell.all('wlan0')[0]
    >>> scheme = Scheme.for_cell('wlan0', 'home', cell)
    >>> scheme.save()
    >>> scheme.activate()

Once you have a scheme saved, you can retrieve it using :meth:`Scheme.find`. ::

    >>> scheme = Scheme.find('wlan0', 'home')
    >>> scheme.activate()

.. note::

    Activating a scheme will disconnect from any other scheme before connecting.

    You must be root to connect to a network.
    Wifi uses `ifdown` and `ifup` to connect and disconnect.


.. autoclass:: Cell
    :members:

.. autoclass:: Scheme
    :members:
