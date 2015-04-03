#!/usr/bin/env python
""" wraith
Wireless assault, reconnaissance, collection and exploitation toolkit.

Requires:
 linux (preferred 3.x kernel)
 Python 2.7
 iw 3.17 (can be made to work w/ 3.2
 postgresql 9.x (tested on 9.3.5)
 pyscopg 2.5.3
 mgrs 1.3.1 (works w/ 1.1)
 dateutil 2.3
 PIL (python-pil,python-imaging-tk,tk8.5-dev tcl8.5-dev) NOTE: I had to unistall
  python-pil and reinstall after installing tk8.5 and tcl8.5

wraith 0.0.2
 desc: dyskt,nidus are developmentally sound, begin work on gui
 includes: wraith-rt. py,subpanels.py and wraith.conf (also all subdirectories etc)
 changes:
  - added multiple panels for non-data related functionality
  - began adding calculation panels

 TODO:
  1) tried --remove-pid/--remove-pidfile to remove pids of dysktd and nidusd
     from /var/run but does not work. Have to use --make-pid to force creation
     of pid file but then, the pidfile is not removed (ubuntu does not have
     --remove-pid flag
  2) make tkMessageBox,tkFileDialog and tkSimpleDialog derive match
    main color scheme
  5) move display of log panel to after intializiation() so that
     wraith panel is 'first', leftmost panel - will have implement mechanism
     to send 'batch' messages after the fact
  6) need to periodically recheck state -> status of postgres,nidusd and dyskt
 10) get log panel to scroll automatically
 11) add labels to frames. Have to use grid or pack not both otherwise, LabelFrame
     throws an error
 13) viewniduslog and viewdysktlog hang whenever respective logs are cleared
 14) need to further test config panels primarily DySKTConfigPanel
 15) see 11, need to convert all pack to grid (or vice versa)
"""
__name__ = 'wraith'
__license__ = 'GPL v3.0'
__version__ = '0.0.2'
__date__ = 'March 2015'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Development'

#### CONSTANTS

BINS = "ABCDEFG"                        # data bin ids
NIDUSLOG   = '/var/log/wraith/nidus.log' # path to nidus log
DYSKTLOG   = '/var/log/wraith/dyskt.log' # path to dyskt log
NIDUSPID   = '/var/run/nidusd.pid'       # path to nidus pidfile
DYSKTPID   = '/var/run/dysktd.pid'       # path to dyskt pidfile
WRAITHCONF = 'wraith.conf'               # path to wraith config file
NIDUSCONF  = 'nidus/nidus.conf'          # path to nidus config file
DYSKTCONF  = 'dyskt/dyskt.conf'          # path to dyskt config file