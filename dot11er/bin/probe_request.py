#!/usr/bin/python

import sys
import redis

from dot11er.state_machine import probe_request
from dot11er.util import start_process

if __name__ == '__main__':
    
    # TODO add appropriate cmd line parsing
    redis_host = 'localhost'
    redis_port = 6379
    redis_db   = 0

    p_probe_request = start_process(probe_request, \
            (redis.StrictRedis(redis_host, redis_port, redis_db),))

    p_probe_request.join()
