The wifi Command
================

This library comes with a command line program for managing and saving your WiFi connections.

Tutorial
^^^^^^^^

This tutorial assumes you are comfortable on the command line.
(If you aren't, perhaps wifi is not quite the right for you.)

First, if you haven't already, install wifi.

.. code-block:: sh

    $ pip install wifi

Now, you want to see what networks are available.
You can run the ``scan`` command to do that.

.. note::
    All of these commands need to run as a superuser.

.. code-block:: sh

    # wifi scan
    -61  SomeNet                  protected
    -62  SomeOtherNet             unprotected
    -78  zxy-12345                protected
    -86  TP-LINK_CB1676           protected
    -86  TP-LINK_PocketAP_D8B616  unprotected
    -82  TP-LINK_C1DBE8           protected
    -86  XXYYYYZZZ                protected
    -87  Made Up Name             protected

The scan command returns three bits of data: the signal quality, the SSID and if the network is protected or not.
If you want to order the networks by quality, you can pipe the output into sort.

.. code-block:: sh

    # wifi scan | sort -rn
    -61  SomeNet                  protected
    -62  SomeOtherNet             unprotected
    -78  zxy-12345                protected
    -82  TP-LINK_C1DBE8           protected
    -86  XXYYYYZZZ                protected
    -86  TP-LINK_PocketAP_D8B616  unprotected
    -86  TP-LINK_CB1676           protected
    -87  Made Up Name             protected

The greater the number, the better the signal.

We decide to use the ``SomeNet`` network because that's the closest one (plus we know the password).
We can connect to it directly using the ``connect`` command.

.. code-block:: sh

    # wifi connect --ad-hoc SomeNet
    passkey>

The ``--ad-hoc`` or ``-a`` option allows us to connect to a network that we haven't configured before.
The wifi asks you for a passkey if the network is protected and then it will connect.

If you want to actually save the configuration instead of just connecting once, you can use the ``add`` command.

.. code-block:: sh

    # wifi add some SomeNet
    passkey>

``some`` here is a nickname for the network you can use when you want to connect to the network again.
Now we can connect to the saved network if you want using the ``connect`` command.

.. code-block:: sh

    # wifi connect some
    ...

If you wish to see all the saved networks, you can use the ``list`` command.


.. code-block:: sh

    # wifi list
    some

Usage
^^^^^

::

    usage: wifi {scan,list,config,add,connect,init} ...

scan
----

Shows a list of available networks. ::

    usage: wifi scan

list
----

Shows a list of networks already configured. ::

    usage: wifi list

add, config
-----------

Prints or adds the configuration to connect to a new network. ::

    usage: wifi config SCHEME [SSID]
    usage: wifi add SCHEME [SSID]

    positional arguments:
      SCHEME      A memorable nickname for a wireless network. If SSID is not
                  provided, the network will be guessed using SCHEME.
      SSID        The SSID for the network to which you wish to connect. This is
                  fuzzy matched, so you don't have to be precise.

connect
-------

Connects to the network corresponding to SCHEME. ::

    usage: wifi connect [-a] SCHEME

    positional arguments:
      SCHEME        The nickname of the network to which you wish to connect.

    optional arguments:
      -a, --ad-hoc  Connect to a network without storing it in the config file

autoconnect
-----------

Searches for saved schemes that are currently available and connects to the
first one it finds. ::

    usage: wifi autoconnect


Completion
^^^^^^^^^^

The wifi command also comes packaged with completion for bash.
If you want to write completion for your own shell, wifi provides an interface for extracting completion information.
Please see the ``wifi-completion.bash`` and ``bin/wifi`` files for more information.
