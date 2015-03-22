# Class: wireless-tools
#
# This class installs wireless-tools
#
# Actions:
#   - Install the wireless-tools package
#
# Sample Usage:
#  class { 'wireless-tools': }
#
class wireless-tools {
  package { 'wireless-tools':
    ensure => latest,
  }
}
