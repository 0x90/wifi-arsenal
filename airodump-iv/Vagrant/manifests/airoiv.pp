# Class: airoiv
#
# This class installs source for airoiv and dependant modules
# This produces a good test environment for wifi pen testing
#
# Sample Usage:
#  class { 'airoiv': }
#
class airoiv {
  require git
  require python-scapy
  require iw
  require wireless-tools
  require aircrack-ng

  vcsrepo { "/home/vagrant/airov":
    ensure => present,
    provider => git,
    source => "git://github.com/ivanlei/airodump-iv.git"
  }
}

class { 'airoiv': }

