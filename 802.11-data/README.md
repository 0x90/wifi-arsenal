802.11-data
===========

Formulas and constants from the 802.11 standards, in machine-readable formats.  I'm surprised this isn't already out there somewhere, but I couldn't find it.  I will attempt to keep this correct, but not exhaustive.  I'm adding information when I have a use for it.  Please do likewise!

Raw Data
--------

Data straight from the standards documents, processed as little as possible:

* [raw/MCS_HT.tab](raw/MCS_HT.tab) MCS parameter tables for High-Throughput PHY (that is, 802.11 / Clause 20).  Note that this file contains multiple tables, not all of which have the same column structure.

Software
--------

* [python/constants.py](python/constants.py)  MCS parameter tables wrapped with a little Python so you don't have to think about the text file format (much).
* [python/funcs.py](python/funcs.py) Support code for constants.py.

