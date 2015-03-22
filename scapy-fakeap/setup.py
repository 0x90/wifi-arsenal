from setuptools import setup, find_packages

setup(
    name='scapy-fakeap',
    version='0.1',
    packages=find_packages(),
    url='',
    license='GPLv2',
    author='rpp0',
    author_email='red@nostack.net',
    requires=['scapy'],
    description='Fake AP implementation using Scapy'
)
