
Locking in the transmit path of ath9k
=====================================


Overview
--------

There's a bunch of state and hardware access that needs to be correctly
sequenced.

* Reading, Writing and resetting the hardware TX queues;
* Maintaining the software side of the hardware TX queues
  (ie, the list of frames currently queued to the hardware
  and awaiting hardware queuing);
* The per-node and per-TID state used for handling aggregation,
  software retransmission, filtered frames, queue draining,
  BAR handling, power save state transitions, sequence numbers
  and the like;
* Scheduling TIDs and AC's in the software queue;
* Running the software queue.

This all requires locking and serialisation in order to keep things
sane.

However - locking is rarely sane.


The Thirty Second Version
-------------------------

* There's a single lock per hardware transmit queue - "struct ath_txq";
  field axq_lock;
* The lock protects the hardware queue AND all of the TIDs which map
  to the hardware queue;
* .. yes, this means that there's a fixed TID -> hardware TXQ mapping;
* ath_txq_lock() locks the given hardware TXQ;
* ath_txq_unlock() unlocks the given hardware TXQ;
* ath_tx_complete() will queue completed frames to the hardware TXQ
  completion queue;
* ath_txq_unlock_complete() unlocks the given hardware TXQ and then
  calls the ieee80211_tx_status() on each of the given frames - this
  way the actual mac80211 status update is called _outside_ of the
  lock context.


Where'd it all come from?
-------------------------

This particular locking scheme is inherited from the original Madwifi
driver.  The Atheros reference driver inherited this locking scheme
and extended it to cover the per-TID state when it introduced TX
aggregation for 11n chipsets.

The ath9k driver extended the TX completion locking to hold the lock
for longer and delay calling the mac80211 callback until after the
TXQ is unlocked.  This neatly avoids a whole lot of lock ordering
and lock contention issues, as mac80211 may decide to try rescheduling
frames (and thus call the transmit path again.)


How is it used?
---------------

The lock is grabbed:

* Whenever the hardware queue state is being updated - eg queuing a frame
  to the hardware; checking frame completion.

* Whenever frame TX for a TID is occuring - eg see which lock is grabbed
  when xmit.c:ath_tx_start() is called.  It maps the TID to a hardware
  queue, then uses that lock to protect it.

* Whenever changing the state of a given TID - eg, pause/unpause of the
  queue, upating the BAW, etc.

* During frame completion - this involves modifying the TID state (eg
  when doing BAW updates.)

During frame completion, the TXQ lock is held.  Any frames which are
completed are pushed into the hardware TXQ completion list (txq->complete_q)
so the lock doesn't have to be dropped.  The driver holds the TXQ lock
whilst completing multiple frames during a call to ath_tx_processq().

Once frame processing is completed, ath_txq_unlock_complete() is called.
This unlocks the TXQ and will pass the completed frames to mac80211
via ieee80211_tx_status().  This is done outside of the lock context.


What are the shortcomings?
--------------------------

The main shortcoming is the 1:1 mapping between TID and the underlying
hardware TXQ.  That hasn't proven to be a problem in practice.

