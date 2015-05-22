from setuptools import setup

setup(name='WPA2-HalfHandshake-Crack',
      version='0.1',
      description='This is a POC to show it is possible to capture enough of a handshake with a user from a fake AP to crack a WPA2 network without an AP',
      url='https://github.com/dxa4481/WPA2-HalfHandshake-Crack',
      author='Dylan Ayrey',
      author_email='dxa4481@rit.edu',
      license='MIT',
      install_requires=['pypcapfile', 'pbkdf2_ctypes'])
