#
# p0f - SYN+ACK fingerprints
# --------------------------
#
# .-------------------------------------------------------------------------.
# | The purpose of this file is to cover signatures for outgoing TCP/IP     |
# | connections (SYN+ACK packets). This mode of operation can be enabled    |
# | with -A option. Please refer to p0f.fp for information on the metrics   |
# | used to create a signature, and for a guide on adding new entries to    |
# | those files. This database is somewhat neglected, and is looking for a  |
# | caring maintainer.                                                      |
# `-------------------------------------------------------------------------'
#
# (C) Copyright 2000-2006 by Michal Zalewski <lcamtuf@coredump.cx>
#
# Plenty of signatures contributed in bulk by rain forest puppy, Paul Woo and
# Michael Bauer.
#
# Submit all additions to the authors. Read p0f.fp before adding any
# signatures. Run p0f -A -C after making any modifications. This file is
# NOT compatible with SYN, RST+, or stray ACK modes. Use only with -A option.
#
# Feel like contributing? You can run p0f -A -K, then test/tryid -iR nnn...
#
# IMPORTANT INFORMATION ABOUT THE INTERDEPENDENCY OF SYNs AND SYN+ACKs
# --------------------------------------------------------------------
#
# Some systems would have different SYN+ACK fingerprints depending on
# the system that sent SYN. More specifically, RFC1323, RFC2018 and
# RFC1644 extensions sometimes show up only if SYN had them enabled.
#
# Also, some silly systems may copy WSS from the SYN packet you've sent,
# in which case, you need to wildcard the value. Use test/sendsyn.c, which
# uses a distinct WSS of 12345, to test for this condition if unsure.
#
# IMPORTANT INFORMATION ABOUT DIFFERENCES IN COMPARISON TO p0f.fp:
# ----------------------------------------------------------------
#
# - 'A' quirk would be present on almost every signature here. ACK number
#   is unusual for SYN packets, but is a commonplace in SYN+ACK packets,
#   of course. It is still possible to have a signature without 'A', when
#   the ACK flag is present but the value is zero - this, however, is
#   very uncommon.
#
# - 'T' quirk would show up on almost all signatures for systems implementing
#   RFC1323. The second timestamp is only unusual for SYN packets. SYN+ACK
#   are expected to have it set.
#

##########################
# Standard OS signatures #
##########################

# ---------------- Linux -------------------

32736:64:0:44:M*:A:Linux:2.0
S22:64:1:60:M*,S,T,N,W0:AT:Linux:2.2
S22:64:1:52:M*,N,N,S,N,W0:A:Linux:2.2 w/o timestamps

5792:64:1:60:M*,S,T,N,W0:AT:Linux:older 2.4
5792:64:1:60:M*,S,T,N,W0:ZAT:Linux:recent 2.4 (1)
S4:64:1:44:M*:ZA:Linux:recent 2.4 (2)
5792:64:1:44:M*:ZA:Linux:recent 2.4 (3)

S4:64:1:52:M*,N,N,S,N,W0:ZA:Linux:2.4 w/o timestamps

# --------------- Windows ------------------

65535:128:1:64:M*,N,W0,N,N,T0,N,N,S:A:Windows:2000 SP4
S44:128:1:64:M*,N,W0,N,N,T0,N,N,S:A:Windows:XP SP1
S12:128:1:64:M*,N,W0,N,N,T0,N,N,S:A:Windows:2000 (SP1+)
S6:128:1:44:M*:A:Windows:NT 4.0 SP1+
65535:128:1:48:M*,N,N,S:A:Windows:98 (SE)
65535:128:1:44:M*:A:Windows:2000 (1)
16616:128:1:44:M*:A:Windows:2003
16384:128:1:44:M*:A:Windows:2000 (2)
S16:128:1:44:M*:A:Windows:2000 (3)

# ------------------- OpenBSD --------------

17376:64:1:64:M*,N,N,S,N,W0,N,N,T:AT:OpenBSD:3.3

# ------------------- NetBSD ----------------

16384:64:0:60:M*,N,W0,N,N,T0:AT:NetBSD:1.6

# ----------------- HP/UX ------------------

32768:64:1:44:M*:A:HPUX:10.20

# ----------------- Tru64 ------------------

S23:60:0:48:M*,N,W0:A:Tru64:5.0 (1)
65535:64:0:44:M*:A:Tru64:5.0 (2)

# ----------------- Novell -----------------

6144:128:1:52:M*,W0,N,S,N,N:A:Novell:Netware 6.0 (SP3)
32768:128:1:44:M*:A:Novell:Netware 5.1

# ------------------ IRIX ------------------

60816:60:1:60:M*,N,W0,N,N,T:AT:IRIX:6.5.0

# ----------------- Solaris ----------------

49232:64:1:64:N,N,T,M*,N,W0,N,N,S:AT:Solaris:9 (1)
S1:255:1:60:N,N,T,N,W0,M*:AT:Solaris:7
24656:64:1:44:M*:A:Solaris:8
33304:64:1:60:N,N,T,M*,N,W1:AT:Solaris:9 (2)

# ----------------- FreeBSD ----------------

65535:64:1:60:M*,N,W1,N,N,T:AT:FreeBSD:5.0
57344:64:1:44:M*:A:FreeBSD:4.6-4.8
65535:64:1:44:M*:A:FreeBSD:4.4

57344:64:1:48:M1460,N,W0:A:FreeBSD:4.6-4.8 (wscale)
57344:64:1:60:M1460,N,W0,N,N,T:AT:FreeBSD:4.6-4.8 (RFC1323)

# ------------------- AIX ------------------

S17:255:1:44:M536:A:AIX:4.2

S12:64:0:44:M1460:A:AIX:5.2 ML04 (1)
S42:64:0:44:M1460:A:AIX:5.2 ML04 (2)

# ------------------ BSD/OS ----------------

S6:64:1:60:M1460,N,W0,N,N,T:AT:BSD/OS:4.0.x

# ------------------ OS/390 ----------------

2048:64:0:44:M1460:A:OS/390:?

# ------------------ Novell ----------------

6144:128:1:44:M1400:A:Novell:iChain 2.2

# ------------------ MacOS -----------------

33304:64:1:60:M*,N,W0,N,N,T:AT:MacOS:X 10.2.6

#################################################################
# Contributed by Ryan Kruse <rkruse@alterpoint.com> - trial run #
#################################################################

# S4:255:0:44:M1024:A:Cisco:LocalDirector
# 1024:255:0:44:M536:A:Cisco,3COM,Nortel:CatIOS,SuperStack,BayStack
# S16:64:0:44:M512:A:Nortel:Contivity
# 8192:64:0:44:M1460:A:Cisco,Nortel,SonicWall,Tasman:Aironet,BayStack Switch,Soho,1200
# 4096:255:0:44:M1460:A:Cisco:PIX,CatOS
# 8192:128:0:44:M1460:A:Cisco:VPN Concentrator
# 8192:128:0:60:M1460,N,W0,N,N,T:AT:Cisco:VPN Concentrator
# 4096:32:0:44:M1460:A:Cisco,3COM,Extreme,Nortel:Catalyst Switch CatOS,CoreBuilder,Summit,Passport
# S4:255:0:44:M536:ZA:Cisco:IOS
# 1024:32:0:44:M1480:UA:Nortel:BayStack Switch
# 4096:60:0:44:M1460:A:Adtran:NetVanta
# 4096:64:0:44:M1008:A:Adtran:TSU
# S4:32:0:44:M1024:A:Alcatel:Switch
# S8:255:0:44:M536:ZA:Cisco:IOS
# 50:255:0:44:M536:ZA:Cisco:CatIOS
# 512:64:0:40:.:A:Dell:Switch
# 4096:64:0:40:.:A:Enterasys:Vertical Horizon Switch
# 17640:64:1:44:M1460:A:F5,Juniper,RiverStone:BigIP,Juniper OS,Router 7.0+
# 16384:64:0:44:M1460:A:Foundry,SonicWall:BigIron,TZ
# 4096:64:0:44:M1452:A:HP:ProCurve Switch
# 1024:64:0:44:M1260:A:Marconi:ES
# 10240:30:0:44:M1460:A:Milan:Switch
# 4096:64:0:44:M1380:A:NetScreen:Firewall
# S32:64:0:44:M512:A:Nokia:CheckPoint
# 1024:64:0:44:M536:A:Nortel:BayStack Switch
# 4128:255:0:44:M*:ZA:Cisco:IOS
# 1024:16:0:44:M536:A:Nortel:BayStack Switch
# 1024:30:0:44:M1480:A:Nortel:BayStack Switch
# S4:64:0:44:M1460:A:Symbol:Spectrum Access Point
# S2:255:0:44:M512:A:ZyXEL:Prestige
# S16:255:0:44:M1024:A:ZyXEL:ZyAI

###########################################
# Appliance / embedded / other signatures #
###########################################

16384:64:1:44:M1460:A:F5:BigIP LB 4.1.x (sometimes FreeBSD)
4128:255:0:44:M*:ZA:Cisco:Catalyst 2900 12.0(5)
4096:60:0:44:M*:A:Brother:HL-1270N
S1:30:0:44:M1730:A:Cyclades:PR3000
8192:64:1:44:M1460:A:NetApp:Data OnTap 6.x
5792:64:1:60:W0,N,N,N,T,M1460:ZAT:FortiNet:FortiGate 50
S1:64:1:44:M1460:A:NetCache:5.3.1
S1:64:0:44:M512:A:Printer:controller (?)
4096:128:0:40:.:A:Sequent:DYNIX 4.2.x
S16:64:0:44:M512:A:3Com:NBX PBX (BSD/OS 2.1)
16000:64:0:44:M1442:A:CastleNet:DSL router
S2:64:0:44:M32728:A:D-Link:DSL-500
S4:60:0:44:M1460:A:HP:JetDirect A.05.32
8576:64:1:44:M*:A:Raptor:firewall
S12:64:1:44:M1400:A:Cequrux Firewall:4.x
2048:255:0:44:M1400:A:Netgear:MR814
16384:128:0:64:M1460,N,W0,N,N,T0,N,N,S:A:Akamai:??? (1)
16384:128:0:60:M1460,N,W0,N,N,T0:A:Akamai:??? (2)

8190:255:0:44:M1452:A:Citrix:Netscaler 6.1

# Whatever they run. EOL boys...
S6:128:1:48:M1460,E:PA:@Slashdot:or BusinessWeek (???)


