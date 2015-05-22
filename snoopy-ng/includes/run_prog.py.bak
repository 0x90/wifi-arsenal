#!/usr/bin/env python
# -*- coding: utf-8 -*-

from subprocess import Popen, call, PIPE
import errno
from types import *
import logging
import sys

#TODO: Implement timeout mechansim

def run_program(rcmd):
    """
    Runs a program 'executable' with list of paramters 'executable_options'. Returns True if program ran successfully.
    """
    #assert type(executable_options) is ListType, "executable_options should be of type list (not %s)" % type(executable_options)
    logging.info("Recvd command '%s'"%rcmd)
    cmd = rcmd.split(' ')
    executable = cmd[0]
    executable_options=cmd[1:]

    try:
        proc  = Popen(([executable] + executable_options), stdout=PIPE, stderr=PIPE)
        response = proc.communicate()
        response_stdout, response_stderr = response[0], response[1]
    except OSError, e:
        if e.errno == errno.ENOENT:
            logging.error( "Unable to locate '%s' program. Is it in your path?" % executable )
            return "%s: command not found" % executable
        else:
            logging.error( "O/S error occured when trying to run '%s': \"%s\"" % (executable, str(e)) )
            return "An error occured when trying to run %s" % executable
    except ValueError, e:
        logging.error( "Value error occured. Check your parameters." )
        return "Bad parameters"
    else:
        if proc.wait() != 0:    
            logging.error( "Executable '%s' returned with the error: \"%s\"" %(executable,response_stderr) )
            return response_stderr
        else:
            logging.debug( "Executable '%s' returned successfully. First line of response was \"%s\"" %(executable, response_stdout.split('\n')[0] ))
            return response_stdout

if __name__ == "__main__":
    run_program(sys.argv[1])
