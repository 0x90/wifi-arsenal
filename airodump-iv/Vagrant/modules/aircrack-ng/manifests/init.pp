# Class: aircrack-ng
#
# This class installs aircrack-ng tools
#
# Actions:
#   - Installs the aircrack-ng package
#
# Sample Usage:
#  class { 'aircrack-ng': }
#
class aircrack-ng {
    package { 'aircrack-ng':
      ensure => latest,
    }
}
