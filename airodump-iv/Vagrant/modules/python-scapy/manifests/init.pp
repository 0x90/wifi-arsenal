# Class: python-scapy
#
# This class installs python-scapy
#
# Actions:
#   - Install the python-scapy package
#
# Sample Usage:
#  class { 'python-scapy': }
#
class python-scapy {
  package { 'python-scapy':
    ensure => latest,
  }
}
