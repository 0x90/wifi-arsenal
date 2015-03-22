class parseEther:
    """
    process various ethernet packets
    """
    def processArp(frame):
        """
        check if a frame is an arp
        return tuple object if it is
        return false if its not
        """
        if frame[12:13] == "\x80\x06":
            # arp packet found
            rmac = frame[22:27]
            rip = frame[28:31]
            uip = frame[38:]
            return (rmac, rip, uip)
        else:
            return False
