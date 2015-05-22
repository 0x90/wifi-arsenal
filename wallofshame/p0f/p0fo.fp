#
# p0f - stray ACK signatures
# --------------------------
#
# .-------------------------------------------------------------------------.
# | The purpose of this file is to cover signatures for stray ACK packets   |
# | (established session data). This mode of operation is enabled with -O   |
# | option and is HIGHLY EXPERIMENTAL. Please refer to p0f.fp for more      |
# | information on the metrics used and for a guide on adding new entries   |
# | to this file. This database is looking for a caring maintainer.         |
# `-------------------------------------------------------------------------'
#
# (C) Copyright 2000-2006 by Michal Zalewski <lcamtuf@coredump.cx>
#
# Submit all additions to the authors. Read p0f.fp before adding any
# signatures. Run p0f -O -C after making any modifications. This file is
# NOT compatible with SYN, SYN+ACK or RST+ modes. Use only with -O option.
#
# IMPORTANT INFORMATION ABOUT THE INTERDEPENDENCY OF SYNs AND ACKs
# ----------------------------------------------------------------
#
# Some systems would have different ACK fingerprints depending on the initial
# SYN or SYN+ACK received from the other party. More specifically, RFC1323,
# RFC2018 and RFC1644 extensions sometimes show up only if the other party had 
# them enabled. Hence, the reliability of ACK fingerprints may be affected.
#
# IMPORTANT INFORMATION ABOUT DIFFERENCES IN COMPARISON TO p0f.fp:
# ----------------------------------------------------------------
#
# - Packet size MUST be wildcarded. ACK packets, by their nature, have 
#   variable sizes, depending on the amount of data carried as a payload.
#  
# - Similarly, 'D' quirk is not checked for, and is not allowed in signatures 
#   in this file. A good number of ACK packets have payloads.
#
# - PUSH flag is excluded from 'F' quirk checks in this mode.
#
# - 'A' quirk is not a bug; all AC packets should have it set; also,
#   'T' quirk is not an anomaly; its absence on systems with T option is.
#

32767:64:1:*:N,N,T:AT:Linux:2.4.2x (local?)
*:64:1:*:.:A:Linux:2.4.2x
32736:64:0:*:.:A:Linux:2.0.3x

57600:64:1:*:N,N,T:AT:FreeBSD:4.8
%12:128:1:*:.:A:Windows:XP
S44:128:1:*:.:A:Windows:XP
