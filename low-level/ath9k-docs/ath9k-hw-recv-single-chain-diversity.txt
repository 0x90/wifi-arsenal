
Receive diversity for single chain 11n devices
==============================================

The single-chain 11n parts (AR9285, AR9271, AR9485) re-introduced the concept
of "antenna switch" diversity, along with some fun extensions that are worth
noting.


How did it work on pre-11n chips?
---------------------------------

With pre-11n chips, the diversity was implemented by using an external
antenna switch and then some hooks into various parts of the NIC to
facilitate antenna selection.

* There's a default antenna which is used when the NIC is currently
  idle.

* There's an antenna configuration stored in the keycache for each
  associated station.

* The PHY side changes from the default to the non-default antenna
  during the initial packet preamble reception, in order to try
  and figure out which antenna gives a stronger signal (ie, what
  is called "fast diversity.")

* The MAC side uses the same antenna to transmit a reply (eg an ACK)
  as the antenna configuration that it received the frame on.

* The driver can decide to change the antenna configuration per-frame
  and globally, based on feedback from the hardware - this is called
  "slow diversity."

What about with MIMO 11n devices?
---------------------------------

Starting with the AR5416 (well, with the AR5513, but that wasn't 11n!)
the PHY implemented MIMO for transmit and receive.  Instead of relying
on fast / slow diversity, the PHY used all the signals seen at all
the antennas and does a whole lot of number crunching on them.
No, the details aren't important here (but google things like
"Maximum-ratio combining") to begin to understand what's going on.


.. wait, but now there's old diversity for new NICs?
----------------------------------------------------

For the 1x1 devices (AR9285, AR9287, AR9485), there is still a need for
multiple antenna support.  It turns out that having "spatial diversity"
(a fancy name for "same signal, but from two slightly different points
in space", or "two antennas") is still really important.

So the AR9285 introduced two-antenna receive diversity, but kept with
a single antenna for transmit.

* There's two LNAs (low-noise amplifiers) inside the AR9285 - called
  LNA1 and LNA2.

* There's two outputs - main and alt antenna.

* Transmission can only occur on main - there's no transmit path
  on the alt (thus it's only receive diversity.)

* Since the main antenna (connected to LNA1) is also used for transmit,
  there's an internal antenna switch connecting that antenna output
  to either transmit, or LNA1 for receive.

* .. so, the receive signal strength level on LNA1 is a few (3?) dB
  less than receiving on LNA2.

* There's an optional external antenna switch on the AR9285,
  to support classic fast diversity with transmit diversity.

* The hardware has a concept of a "main" and "alternate" antenna
  configuration - and these have to do with how the LNA signals
  are added together:

  + LNA1
  + LNA2
  + LNA1 - LNA2
  + LNA1 + LNA2

* Like the pre-11n hardware, the PHY can be configured to do "fast
  diversity" - ie, it can control the external antenna switch to
  try antenna 1 or 2.

* The PHY also implements "combined diversity" -  it will try to sample
  the RSSI on both the primary and alternate antenna configuration during
  the preamble.  But instead of it selecting just one antenna or the other,
  it will try the main antenna configuration and then the alternate
  antenna configuration.


How's this all controlled?
--------------------------

In keeping with the ath9k tradition of "look at the driver source",
the best place to look at how this is all glued together is the
combined diversity code in the ath9k driver.

So, look at antenna.c.

Now, just to make the frame format descriptions clearer, the LNA
configuration options are as follows:

    | 0 |  LNA1 - LNA2  |
    | 1 |  LNA2         |
    | 2 |  LNA1         |
    | 3 |  LNA1 + LNA2  |


How does the driver get feedback?
---------------------------------

Since there's only two antennas on these devices, the third RSSI
entry in the RX completion descriptor is re-used as an antenna
and LNA configuration report.

So, instead of Primary channel RSSI for chain 2, this is what
is reported:

  * Bit[7]          LNA config used to receive frame
                    (0->"Main" or 1->"Alternate")
  * Bit[6]          ext diversity antenna used to receive frame
                    (0->ant1 or 1->ant2)
  * Bit[5:4]        LNA config used to receive frame,
  * Bit[3:2]        LNA config used for "Main",
  * Bit[1:0]        LNA config used for "Alternate".

And instead of Extension channel RSSI for chain 2, this is
what is reported:

  * Bit[7]          0, not used
  * Bit[6]          Fast diversity measurement executed on this frame?
                    (0->no or 1->yes)
  * Bit[5:4]        output of BB switchtables: sw_0[1:0]
  * Bit[3:0]        output of BB switchtables: sw_com[3:0]


How's this differ for the AR9271?
---------------------------------

In short: it doesn't.


How's this differ for the AR9485?
---------------------------------

The AR9485 uses an external antenna switch for both receive and
transmit diversity.  The important bit here - there's no receive
signal level difference between the two antenans.

Other than that, the feedback and LNA configuration is the same.
