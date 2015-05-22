
How the ath9k transmit path works
=================================

The ath9k transmit path handles frame transmission, aggregation, software
retransmission and various miscellaneous tasks (such as filtered frames.)

This document outlines the flow of frames through the transmit path.
It doesn't cover how the hardware itself works - ie, how the legacy
versus FIFO DMA queues work, or how the QCU/DCU units function.
This will be covered in a different document.


Overview
--------

The mac80211 layer keeps a queue of frames destined to each station as
well as a pending queue per-TID for various things (aggregation staging,
power-save frames, filtered frames.)

The ath9k driver maintains a separate set of state per node (struct ath_node)
as well as some state per-TID (ath_atx_tid.)  This is used for frame
transmission and aggregation.

The driver takes care of frame aggregation, transmission and completion
status.  Frames are then handed back to mac80211 via ieee80211_tx_status()
which will either complete the frame, or push it back into a mac80211
queue (eg filtered frames) for a further transmission attempt.

When transmitting aggregate frames, the hardware expects a list of
frames to be assembled in one A-MPDU list.  Unlike firmware based NICs
which will aggregate individual frames in firmware, the driver must
queue frames for a given node/TID and when it is appropriate, push the
entire list of frames to the hardware.  In addition, when handling
block-ACK completion, the driver needs to complete/free only those
frames that were successfully transmitted and re-queue those that
failed.


Queuing frames to the hardware
------------------------------

Frames are queued to the hardware via a call to xmit.c:ath_tx_txqaddbuf().
This handles pushing frames into the DMA engine as appropriate (EDMA
or legacy) as well as starting DMA if required.


Frame transmission status and completion
----------------------------------------

Whenever the hardware finishes transmitting a frame (successfully or
otherwise), xmit.c:ath_tx_process_buffer() is called to update local
state and statistics.

The frame status in the 'struct ieee80211_tx_info' field is updated with
the transmission status via a call to ath_tx_rc_status().  mac80211
will eventually be handed the frame via a call to ieee80211_tx_status().

A non-aggregate session frame ends up calling xmit.c:ath_tx_complete_buf().
This stamps the frame completion timestamp and filtered frame status,
and then unmaps the DMA mapping.

An aggregate-session frame ends up calling xmit.c:ath_tx_complete_aggr().
This handles matching each A-MPDU sub-frame against the queued frames
and completing / retrying each as appropriate.


Frame setup, rate control and other options
-------------------------------------------

Each frame from mac80211 is tagged with a 'struct ieee80211_tx_info' which
describes the tx parameters.  The ath9k driver (mostly) obeys what
the frame setup and rate control values say to do.

The driver fetches the current rate configuration with a call to
xmit.c:ath_set_rates().  This calls mac80211 ieee80211_get_tx_rates()
to fetch the current rate configuration.

The rate information 'struct ieee80211_tx_rate' is a part of
'struct ieee80211_tx_info'.

There are various places where the information from ieee80211_tx_info
is used.  It's best to look through the ath9k xmit.c code and see
where this is used.

xmit.c:ath_tx_fill_desc() fills in some of the descriptor fields - such
as whether an ACK is required and whether to use LDPC.  These fields
are _global_ entries for the given frame - ie, they are the same for
all the different transmission attempts for this frame.

xmit.c:ath_buf_set_rate() fills in the transmission rate table information.
This includes the TX rate to use, frame duration, STBC, RTS/CTS, channel
width and preamble type.  These may change for the (up to 4) different
rate attempts for this frame.

Important things to note:

* the basic frame transmission information (eg ACK status) is setup
  by mac80211 (in 'struct ieee80211_tx_info') before it hands it to
  the driver.

* the rate table is populated via a call to ieee80211_get_tx_rates()
  just before the frame is dispatched to the hardware queue.


Initial frame transmission
--------------------------

The initial frame transmission begins in main.c:ath9k_tx().

This will call xmit.c:ath_tx_start() with the frame to send.
ath_tx_start() adds any frame padding that is required, picks
a destination hardware queue and checks to see whether
aggregation is enabled.  If aggregation is enabled, the frame
is passed to ath_tx_send_ampdu(). If aggregation is not enabled,
the frame rate information is fetched from mac80211 via
a call to ath_set_rates(), then is dispatched via ath_tx_send_normal().

There are a few paths that frame transmission can take:

* If the frame is in a non-aggregate TID, it is directly dispatched
  to the hardware queue via ath_tx_send_normal().

* If the frame is in an aggregate TID, it may be direct dispatched
  or queued in a software queue for future transmission.

Handling filtered frames
-------------------------------------

The MAC can track whether transmission to a node is continuously failing
and if so, the MAC will stop transmitting any further frames to the
node.  That way it doesn't waste air time trying to transmit to a node
that isn't available or awake; it completes each frame immediately
with the ATH9K_TXERR_FILT bit set in the TX status field.

If the CLRDMASK bit is set in a TX descriptor, the MAC will clear
the "filtered" bit for the given node and force the next transmission
to be attempted.

The implementation however is a little tricky as it involves both
mac80211 and the driver.

* If a frame completes with ATH9K_TXERR_FILT set, the ieee80211_tx_info
  flags field is marked with IEEE80211_TX_STAT_TX_FILTERED.

* ieee80211_tx_status() is then called with the frame.

* ieee80211_tx_status() will call ieee80211_handle_filtered_frame(),
  which clears a bunch of state and pushes the frame into the
  mac80211 station tx_filtered[] queue.  There's one queue per TID.

* When the station wakes up or a PS-POLL frame is received,
  frames will be dequeued from the filtered frames list first
  before servicing other frames.

TODO:

* If an aggregate frame exceeds the retry count as part of a filtered
  frame from the MAC, ath_tx_complete_buf() will mark that sub-frame
  as filtered and pass it up to mac80211 via ieee80211_tx_status().
  I think this causes the frame to be pushed into the mac80211
  filtered frame queue.  But it's already been retransmitted a bunch
  of times with an established sequence number.  Will this cause issues?


Aggregation: Overview
---------------------

In order to gather frames to transmit for A-MPDU transmission, the driver
needs to gather individual frames from mac80211 (via ath9k_tx() ->
ath_tx_start()), store them in the pending frame list ('ath_atx_tid->buf_q')
and then assemble these as an A-MPDU frame to the hardware.

Aggregation: Setup and Teardown
-------------------------------

Although mac80211 handles the ADDBA negotiation and teardown handling,
the driver has hooks into this process so its own local state can be
updated.

* xmit.c:ath_tx_aggr_start() is called when aggregation is being
  setup.  Local state is setup and the TID is paused so setup
  will have time to complete.

* xmit.c:ath_tx_aggr_resume() is called once aggregation setup
  is completed; it unpauses the TID.

* xmit.c:ath_tx_aggr_stop() is called to tear down aggregation.
  This involves marking the TID as draining and flushing out the
  frames in the pending queue.  Once frames in hardware queue
  have completed, the TID will be unpaused.

* xmit.c:ath_tx_aggr_sleep() and xmit.c:ath_tx_aggr_wakeup() are
  called as part of the node power-save handling - this pauses and
  resumes transmission for the given node.


Aggregation: Tracking Block-ack Windows
---------------------------------------

The driver also has to track the current block-ack window for the given
TID in order to know which frames to transmit (ie, inside the block-ack
window) and when to continue queuing frames until retransmission
has completed.

There are two functions which implement this:

* xmit.c:ath_tx_addto_baw() will add the given frame to the block-ack
  window;

* xmit.c:ath_tx_update_baw() will treat the given frame as completed
  and advance the block-ack window along.

The aggregate transmit path then checks whether the a frame sequence
number is within the block-ack window or not.


Aggregation: Software-queued frames and scheduling
--------------------------------------------------

To faciliate aggregation and retransmission, the driver implements a basic
software queue mechanism.

Each TID in a node can be individually scheduled, paused and unpaused.

The TID state for a given node is stored in 'struct ath_atx_tid'.
This includes the queue state and pending frame list for aggregation
(in 'buf_q'.)

To mark a queue as ready to transmit, the driver calls
xmit.c:ath_tx_queue_tid().  If the queue is not paused, the TID is
added to per-AC queue; and the AC is added to the hardware queue.
The driver will then attempt to schedule frames from this TID
when the hardware queue has space for future frames.

A TID is unpaused by calling xmit.c:ath_tx_resume_tid().

A TID is paused by marking 'tid->paused' to true.  This is done when
the driver needs to pause transmission whilst some state change
occurs - eg establishing or tearing down aggregation.

The software queue mechanism is implemented in xmit.c:ath_tx_process_buffer().
This checks the list of active AC/TID entries for the given hardware
queue and attempts to schedule further frames.  It implements a very
simple FIFO scheduling method for each TID/AC for the given hardware
queue.


Aggregation: Assembling frames for aggregation
----------------------------------------------

Instead of implementing a timer to gather frames for transmission, the
driver instead does the following:

* If the number of aggregate session frames in the underlying hardware queue
  (for any TID, not just the one transmitting) is less than
  ATH_AGGR_MIN_QDEPTH, directly schedule a frame to the hardware queue.

* All frames from an aggregate TID are included in the hardware queue
  pending aggregate frame counter (ath_txq->axq_ampdu_depth) - that way
  even the non A-MPDU frames queued cause aggregate session frames to
  be software queued.

* Because it takes a decent amount of time to send a single MPDU -
  due to all of the time spent in frame preamble and frame-spacing -
  this will delay any further transmission by (at least) a few hundred
  microseconds per frame, even at high MCS rates.

* If frames are being scheduled fast enough, they will accumulate in
  the software transmission queue.

* Then, when the frame transmission completes, there will be a handful
  of frames in 'ath_atx_tid->buf_q' queue already, so ..

* .. the next frame transmission attempt can form an aggregate, rather than
  schedule a single frame.

Using the above algorithm, low-latency transmission is still maintained
(as there's no timer used to aggregate frames - a quiet queue results in
instant frame dispatch to hardware) and frames are naturally aggregated
for transmission if enough show up.

The downside? If frames don't come in quickly enough and the medium is
quite clean, you may not end up aggregating frames very efficiently.
Whether this is a problem or not is left as an exercise to the reader.

How this is implemented:

* Frames destined for a node/TID with aggregation enabled are passed to
  xmit.c:ath_tx_send_ampdu();

* If the hardware queue depth is less than ATH_AGGR_MIN_QDEPTH and the
  rest of the aggregate state allows for frames to be transmitted
  (frame sequence number is within the block-ack window; the TID
  isn't paused, etc) then the frame is added to the BAW and directly
  dispatched.

* Otherwise, the frame is added to the node/TID software queue and
  ath_tx_queue_tid() is called to schedule the software queue to
  eventually dispatch frames to this queue.

* xmit.c:ath_tx_processq() is called when the hardware queue has
  finished transmitting something.  This calls ath_txq_schedule()
  to attempt to schedule further frames.

* ath_txq_schedule() will call xmit.c:ath_tx_sched_aggr().

ath_tx_sched_aggr() will attempt to queue aggregate frames to the
hardware up to the ATH_AGGR_MIN_QDEPTH limit.

The actual assembly of an A-MPDU occurs in xmit.c:ath_tx_form_aggr().
This will walk the list of pending frames and assemble an A-MPDU
that meets the relevant restrictions.

* The rate control lookup is done by a call to ath_set_rates()
  when the first frame is removed from the pending list.

* If the frame is outside of the BAW, aggregate assembly stops here
  and transmission on this node/TID will stop until another call
  to ath_txq_schedule() causes this node/TID to be serviced.

* The maximum duration for the aggregate is calculated by a call
  to xmit.c:ath_lookup_rate(), which will calculate the maximum
  allowed aggregate (in bytes) based on the slowest transmission
  rate chosen for this particular aggregate.  A 4ms maximum
  transmission length is imposed on all aggregates.

* Pad delimiters are calculated for each sub-frame in the aggregate.
  This is done to meet the A-MPDU density as negotiated with the
  peer, as well as alignment and padding requirements for the
  revision of chip being used.

* The frame is added to the BAW through a call to ath_tx_addto_baw().

* The aggregate buffer is marked as an A-MPDU so the descriptor setup
  code knows to setup the aggregate fields.


Aggregation: Frame completion
-----------------------------

An aggregate session frame ends up in xmit.c:ath_tx_complete_aggr().
This checks the block-ack status - frames that were successfully ACKed
will complete those frames and update the BAW via a call to
ath_tx_update_baw(); frames that are failed are marked as retry and added
to the pending list (ath_tx_tid->buf_q.)

The rate control status for the aggregate is updated here via a call
to ath_tx_rc_status().

If the queue has more frames to transmit (eg from a retransmission)
then the TID is rescheduled through a call to ath_tx_queue_tid().

If any of the A-MPDU sub-frames have been retransmitted too often,
xmit.c:ath_send_bar() is called to send a BAR.


Aggregation: Frame retransmission
---------------------------------

During aggregation, frames that fail to transmit succesfully need
to be retried. This is doubly important for correct block-ack window
tracking - all the frames inside the current block-ack window need to
be transmitted successfully before the window can advance.

As background information - this doesn't necessarily mean the full window
is filled and transmitted before it is advanced.  If there are any frames
at the head of the current block-ack window which need retransmitting,
the queue will stall.  But the window will be advanced if the frames
at the head of the block-ack window were succesfully transmitted.

But this can't be done indefinitely.  Eventually a limit will be reached
and the frame will be marked as failed.  At this point the receiver needs
to be notified that the block-ack window needs to be moved - this is
where a BAR frame is sent with the new block-ack window information.

Thus, frame retransmission is implemented as such:

* ath_tx_complete_aggr() walks the list of sub-frames in an A-MPDU and
  if it has succeeded, the sub-frame is removed from the BAW as mentioned
  above.

* If a sub-frame fails, the sub-frame is retried only if the retry count
  is less than ATH_MAX_SW_RETRIES and it is marked as a retry frame
  by calling xmit.c:ath_tx_set_retry().  This takes care of marking
  the frame as retry, incrementing the retry counter and re-syncing the
  transmit buffer via a call to dma_sync_single_for_device().

* If any sub-frame fails, the BAR index is calculated and stored in
  bar_index.

* If bar_index has been set, then a call to xmit.c:ath_send_bar() is made
  to send a BAR frame to the remote peer.


Aggregation: BAR transmission
-----------------------------

BAR frame transmission is simple - xmit.c:ath_send_bar() notifies
mac80211 to transmit a BAR frame via a call to ieee80211_send_bar().


How power-save stations work
----------------------------

When a node is in power-save, the driver should stop transmission to
the given node.  It just wastes air time transmitting to a station
which won't actually respond to traffic.

xmit.c:ath_tx_aggr_sleep() and xmit.c:ath_tx_aggr_wakeup() are
called as part of the node power-save handling - this pauses and
resumes transmission for the given node.

ath_tx_aggr_sleep() walks each TID in the node and pauses it.

ath_tx_aggr_wakeup() walks each TID in the node, makes sure CLRDMASK is set
on the next frame by setting clear_ps_filter, and resuming the TID.


Stuff not yet discussed
-----------------------

* flushing node/TID during disassociation/reassociation
* how the deferred ieee80211_tx_status() processing works
  once the TXQ lock is released
* how serialisation and ordering is actually implemented,
  via use of queue disciplines and mac80211. (eg, how
  exactly the sequence numbers assigned in ath_tx_start()
  doesn't end up with out-of-order packets when there's multiple
  transmitting threads.)
* how cleanup works
