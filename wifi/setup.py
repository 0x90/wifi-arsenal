#!/usr/bin/env python
from setuptools import setup
import os

__doc__ = """
Command line tool and library wrappers around iwlist and
/etc/network/interfaces.
"""


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


install_requires = [
    'setuptools',
    'pbkdf2',
]
try:
    import argparse
except:
    install_requires.append('argparse')

version = '1.0.0'

data_files = [
    ('/etc/bash_completion.d/', ['extras/wifi-completion.bash']),
]
for entry in data_files:
    # make sure we actually have write access to the target folder and if not don't
    # include it in data_files
    if not os.access(entry[0], os.W_OK):
        print("Skipping copying files to %s, no write access" % entry[0])
        data_files.remove(entry)

setup(
    name='wifi',
    version=version,
    author='Rocky Meza, Gavin Wahl',
    author_email='rockymeza@gmail.com',
    description=__doc__,
    long_description='\n\n'.join([read('README.rst'), read('CHANGES.rst')]),
    packages=['wifi'],
    scripts=['bin/wifi'],
    test_suite='tests',
    platforms=["Debian"],
    license='BSD',
    install_requires=install_requires,
    classifiers=[
        "License :: OSI Approved :: BSD License",
        "Topic :: System :: Networking",
        "Operating System :: POSIX :: Linux",
        "Environment :: Console",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.3",
    ],
    data_files=data_files
)
