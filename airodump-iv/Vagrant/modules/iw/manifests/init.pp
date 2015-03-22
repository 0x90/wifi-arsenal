# Class: iw
#
# This class installs iw
#
# Actions:
#   - Install the iw package
#
# Sample Usage:
#  class { 'iw': }
#
class iw {
  package { 'iw':
    ensure => latest,
  }
}
