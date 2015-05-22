# -*- coding: utf-8 -*-
from distutils.core import setup

def get_version():
    with open("docs/VERSION") as f:
        version = f.readline()
    return version[:-1]


setup(
    name = "python-wifi",
    version = get_version(),
    author = "Róman Joost",
    author_email = "roman@bromeco.de",
    maintainer = "Sean Robinson",
    maintainer_email = "pythonwifi@lists.tuxfamily.org",
    description = """Python WiFi is a Python module that provides read and write access to a
wireless network card's capabilities using the Linux Wireless Extensions.""",
    url = "http://pythonwifi.tuxfamily.org/",
    packages = ['pythonwifi'],

    data_files=[('', ['README']),
                ('examples', ['examples/iwlist.py', 'examples/iwconfig.py']),
                ('docs', ['docs/AUTHORS', 'docs/BUGS', 'docs/LICENSE.GPL',
                          'docs/LICENSE.LGPL', 'docs/NEWS', 'docs/ROADMAP',
                          'docs/TODO', 'docs/VERSION', 'docs/ChangeLog',
                          'docs/DEVEL.txt',
                          'docs/feature_matrix_iwconfig.py.txt',
                          'docs/feature_matrix_iwlist.py.txt',
                          'docs/feature_matrix_wireless_extensions.txt']),
                ('docs/logos', ['docs/logos/pythonwifi-logo.svg',
                                'docs/logos/pythonwifi-logo-16x16.png',
                                'docs/logos/pythonwifi-logo-64x64.png',
                                'docs/logos/pythonwifi-logo-text.png',
                                'docs/logos/pythonwifi-logo.karbon']),
                ('man/man8', ['docs/iwconfig.py.8', 'docs/iwlist.py.8']),
               ],

    platforms = "Linux",
    license = "LGPL for module; GPL for example apps",
    keywords = "wifi wireless wlan iwconfig iwlist iwtools",
    classifiers = [
        'Development Status :: 3 - Alpha',
        'Environment :: Other Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'License :: OSI Approved :: Lesser General Public License (LGPL)',
        'Natural Language :: English',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Topic :: System :: Networking',
    ],
)
