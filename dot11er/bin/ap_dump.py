#!/usr/bin/python

import sys
import redis

from dot11er.infra import AP_QUEUE,ap_dump,rx_beacon
from dot11er.util import start_process

if __name__ == '__main__':
    
    # TODO add appropriate cmd line parsing
    mon_if = sys.argv[1]

    redis_host = 'localhost'
    redis_port = 6379
    redis_db   = 0

    p_ap_dump = start_process(ap_dump, ( \
            redis.StrictRedis(redis_host, redis_port, redis_db), \
            mon_if))
    p_rx_beacon = start_process(rx_beacon, ( \
            redis.StrictRedis(redis_host, redis_port, redis_db), \
            mon_if))

    r = redis.StrictRedis(redis_host, redis_port, redis_db)
    ps = r.pubsub()
    ps.subscribe(AP_QUEUE(mon_if))
    for m in ps.listen():
        print m['data']

    p_rx_beacon.join()
    p_ap_dump.join()
