Dependencies
==============================================================================

apt:
    - libev-dev
    - python-scapy
    - libpcap-dev
    - libnl-dev

easy_install:
    - pyev
    - python-daemon
    - pytz

src:
    - git clone https://code.google.com/p/lorcon/
        - ./configure
        - make
        - sudo make install
        - cd pylorcon2
            - python setup.py build
            - sudo python setup.py install


