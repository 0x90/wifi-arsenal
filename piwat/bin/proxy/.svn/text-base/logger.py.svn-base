"""
  Copyright notice
  ================
  
  Copyright (C) 2011
      Roberto Paleari     <roberto.paleari@gmail.com>
      Alessandro Reina    <alessandro.reina@gmail.com>
  
  This program is free software: you can redistribute it and/or modify it under
  the terms of the GNU General Public License as published by the Free Software
  Foundation, either version 3 of the License, or (at your option) any later
  version.
  
  HyperDbg is distributed in the hope that it will be useful, but WITHOUT ANY
  WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
  A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
  
  You should have received a copy of the GNU General Public License along with
  this program. If not, see <http://www.gnu.org/licenses/>.
  
"""

import os, sys
import threading

COLOR_RED    = 31
COLOR_GREEN  = 32
COLOR_YELLOW = 33
COLOR_BLUE   = 34
COLOR_PURPLE = 35

def colorize(s, color = COLOR_RED):
    return (chr(0x1B) + "[0;%dm" % color + str(s) + chr(0x1B) + "[0m")

class Logger:
    def __init__(self, verbosity = 0):
        self.verbosity = verbosity

    def __out(self, msg, head, color):
        tid = threading.current_thread().ident & 0xffffffff
        tid = " %s " % colorize("<%.8x>" % tid, COLOR_PURPLE)
        print colorize(head, color) + tid + msg    

    def info(self, msg):
        self.__out(msg, "[*]", COLOR_GREEN)

    def warning(self, msg):
        self.__out(msg, "[#]", COLOR_YELLOW)

    def error(self, msg):
        self.__out(msg, "[!]", COLOR_RED)

    def debug(self, msg):
        if self.verbosity > 0:
            self.__out(msg, "[D]", COLOR_BLUE)
