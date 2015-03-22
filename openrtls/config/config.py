import os

config = {
    # paths relative from this config file
    "pidfile": os.path.realpath(os.path.join(os.path.dirname(__file__),
                                '..', 'var', 'fakeapd.pid')),
    "logfile": os.path.realpath(os.path.join(os.path.dirname(__file__),
                                '..', 'log', 'fakeapd.log')),
    "binpath": os.path.realpath(os.path.join(os.path.dirname(__file__),
                                 '..', 'bin')),

    "debug": False,

    "interface": "mon0",
    "ESSID": "LOVEYOULONGTI.ME",
    "BSSID": "00:1e:ab:20:4b:1d",
    "channel": 1,
    "beacon_interval_sec": 0.1
}

