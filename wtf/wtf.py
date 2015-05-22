#!/usr/bin/python

import sys
import getopt
import os
import nose
import wtf


def usage():
    print """
wtf.py: Test runner for the wireless test framework

Usage: wtf.py [options] <tests>

  -h               Print this message

  -c <cfg>         Config file for the tests.  If this is not provided wtf.py
                   will use ./wtfconfig.py.

  -v               Verbose (i.e., show test names)
  -s               stdout (i.e., show stdout of tests)

  <tests> can be a list of test suites:

  wtf.py ./tests/ap_sta.py ./tests/basic.py

  ...or a list of specific test:

  wtf.py ./tests/ap_sta.py:TestAPSTA.test_open_associate
"""

if __name__ == '__main__':

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hc:vs",
                                   ["help", "configfile=", "verbose", "stdio"])
    except getopt.GetoptError, err:
        print str(err)
        sys.exit(2)

    configfile = "./wtfconfig.py"
    verbose = False
    stdio = False
    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit()
        elif o in ("-c", "--configfile"):
            configfile = a
        elif o in ("-v", "--verbose"):
            verbose = True
        elif o in ("-s", "--stdio"):
            stdio = True
        else:
            assert False, "unhandled option"

    # Import the configuration
    if not os.path.exists(configfile):
        print "Config file " + configfile + " does not exist."
        sys.exit(1)

    path = os.path.abspath(os.path.dirname(configfile))
    sys.path.append(path)
    conf = os.path.basename(configfile)
    if conf.count('.py') != 1:
        print conf + " is a confusing name for a config file.  " + \
            "I can't parse it."
        sys.exit(1)
    if conf.count('.') != 1:
        print "I'm not that smart.  " + \
            "Please don't use '.' as part of your config file name"
        sys.exit(1)

    print "Loading config file " + conf

    conf = conf.replace(".py", "")
    try:
        wtfconfig = __import__(conf)
    except ImportError:
        print "Failed to import " + configfile
        raise

    if not hasattr(wtf, 'conf'):
        print "You must set wtf.conf in your config file"
        sys.exit(1)

    # Find out which tests we're running
    if args == [] and wtf.conf.suite == None:
        print "Please specify some tests to run."
        sys.exit(1)

    if args == []:
        suite = os.path.join(os.path.dirname(__file__), "tests")
        suite = os.path.join(suite, wtf.conf.suite + ".py")
        if not os.path.exists(suite):
            print "Test suite " + suite + " does not exist."
            sys.exit(1)
        args.append(suite)

    # Apply the args
    if verbose:
        args = args + ["-v"]
    if stdio:
        args = args + ["-s"]

    # Now run the tests
    args.append('--with-xunit')
    wtf.conf.setUp()
    print "======================================================================"
    print "Running " + wtf.conf.name
    print "======================================================================"
    nose.run(argv=["wtf.py"] + args)
    wtf.conf.tearDown()
