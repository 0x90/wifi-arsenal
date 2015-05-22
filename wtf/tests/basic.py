# Copyright cozybit, Inc 2010-2011
# All rights reserved

"""
Test init/teardown and start/stop behavior for each configured node

The basic test suite just makes sure that any configured nodes can be
initialized and shutdown repeatedly without hanging, crashing, etc.
"""

import wtf
wtfconfig = wtf.conf


class TestBasic():

    def setUp(self):
        # start with all of the nodes shutdown
        for n in wtfconfig.nodes:
            n.shutdown()

    def test_init_shutdown(self):
        for n in wtfconfig.nodes:
            n.init()
            n.shutdown()
            n.init()
            n.shutdown()
