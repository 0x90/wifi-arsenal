#!/usr/bin/env python
# -*- coding: utf-8 -*-

from subprocess import Popen, call, PIPE
import errno
from types import *
import logging
import sys

def splitz(str):
    """Split a string based on space, but hold quotes"""
    tmp = []
    st = 0
    i = str.find('"',st)
    while i > 0:
        tmp.extend(str[st:i-1].strip().split(" "))
        j = str.find('"', i+1)
        if j < 1:
            return
        tmp.append(str[i+1:j])
        st = j+1
        i = str.find('"',st)
    tmp.extend(str[st:].strip().split(" "))
    return tmp

def run_program(rcmd):
    """
    Runs a program 'executable' with list of paramters 'executable_options'. Returns the process, or None if failed. Use:
        proc.poll() to check if it's running (0 = running)
        proc.kill() to kill the process
    """

    logging.debug("Running command '%s'"%rcmd)
    cmd = splitz(rcmd)
    if not cmd:
        logging.error("Bad command '%s'" %rcmd)
        return
    executable = cmd[0]
    executable_options=cmd[1:]

    try:
        proc  = Popen(([executable] + executable_options), stdout=PIPE, stderr=PIPE)
        #response = proc.communicate()
        #response_stdout, response_stderr = response[0], response[1]
    except OSError, e:
        if e.errno == errno.ENOENT:
            logging.error( "Unable to locate '%s' program. Is it in your path?" % executable )
        else:
            logging.error( "O/S error occured when trying to run '%s': \"%s\"" % (executable, str(e)) )
    except ValueError, e:
        logging.error( "Value error occured. Check your parameters." )
    else:
        return proc

if __name__ == "__main__":
    """Careful, main program will block"""
    proc = run_program(sys.argv[1])
    response = proc.communicate()
    response_stdout, response_stderr = response[0], response[1]
    if proc.wait() != 0:    
        print "Program returned with the error: \"%s\"" %(response_stderr)
        sys.exit(-1) 
    else:
        print "Program returned successfully. First line of response was \"%s\"" %(response_stdout.split('\n')[0] )
        print response_stdout
