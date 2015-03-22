//
//  IntersilJack.mm
//  KisMAC
//
//  Created by Geoffrey Kruse on 5/1/06.
//  Copyright 2006 __MyCompanyName__. All rights reserved.
//

#import "IntersilJack.h"

#define wlcDeviceGone   (int)0xe000404f
#define align64(a)      (((a)+63)&~63)

bool IntersilJack::startCapture(UInt16 channel) {
    if (!_devicePresent) return false;
    if (!_deviceInit) return false;
    
    if ((!_isEnabled) && (_disable() != kIOReturnSuccess)) {
        DBNSLog(@"IntersilJack::startCapture: Couldn't disable card\n");
        return false;
    }
    
    if (setChannel(channel) == false) {
        DBNSLog(@"IntersilJack::startCapture: setChannel(%d) failed - resetting...\n",
              channel);
		_reset();
        return false;
    }
    
    if (_doCommand(wlcMonitorOn, 0) != kIOReturnSuccess) {
        DBNSLog(@"IntersilJack::startCapture: _doCommand(wlcMonitorOn) failed\n");
        return false;
    }
    
    if (_enable() != kIOReturnSuccess) {
        DBNSLog(@"IntersilJack::startCapture: Couldn't enable card\n");
        return false;
    }
    
    _channel = channel;
    return true;
}

bool IntersilJack::stopCapture() {
_channel = 0;

if (!_devicePresent) return false;
if (!_deviceInit) return false;

if (_doCommand(wlcMonitorOff, 0) != kIOReturnSuccess) {
    DBNSLog(@"::stopCapture: _doCommand(wlcMonitorOff) failed\n");
    return false;
}

return true;
}

bool IntersilJack::getChannel(UInt16* channel) {
    if (!_devicePresent) return false;
    if (!_deviceInit) return false;
    
    if (_getValue(0xFDC1, channel) != kIOReturnSuccess) {
        DBNSLog(@"IntersilJack::getChannel: getValue error\n");
        return false;
    }
    
    _channel = *channel;
    return true;
}

bool IntersilJack::getAllowedChannels(UInt16* channels) {
    if (!_devicePresent) return false;
    if (!_deviceInit) return false;
    
    if (_getValue(0xFD10, channels) != kIOReturnSuccess) {
        DBNSLog(@"IntersilJack::getAllowedChannels: getValue error\n");
        return false;
    }
    
    return true;
}

bool IntersilJack::setChannel(UInt16 channel) {
    if (!_devicePresent) return false;
    if (!_deviceInit) return false;
    
    if (_setValue(0xFC03, channel) != kIOReturnSuccess) {
        usleep(10000);
        if (_setValue(0xFC03, channel) != kIOReturnSuccess) {
            DBNSLog(@"IntersilJack::setChannel: setValue error\n");
            return false;
        }
    }
    
    if (_isEnabled) {
        if (_disable() != kIOReturnSuccess) {
            DBNSLog(@"IntersilJack::setChannel: Couldn't disable card\n");
            return false;
        }
        if (_enable() != kIOReturnSuccess) {
            DBNSLog(@"IntersilJack::setChannel: Couldn't enable card\n");
            return false;
        }
    }
    
    _channel = channel;
    return true;
}

char *IntersilJack::getPlistFile()
{
    return (char*)"UsbVendorsIntersil";
}
IOReturn IntersilJack::_init() {
    WLIdentity ident;
    WLHardwareAddress macAddr;
    int i; 
    
    if(!_attachDevice()){
        DBNSLog(@"Device could not be opened");
        return kIOReturnNoDevice;
    }
    
    _firmwareType = -1;
    
    for (i = 0; i< wlResetTries; ++i) {
        if (_reset() == kIOReturnSuccess) break;
        if (!_devicePresent) return kIOReturnError;
    }
    
    /*
     * Get firmware vendor and version
     */
    
    if (_getIdentity(&ident) != kIOReturnSuccess) {
        DBNSLog(@"IntersilJack::_init: Couldn't read card identity\n");
        return kIOReturnError;
    }
    
    DBNSLog(@"IntersilJack: Firmware vendor %d, variant %d, version %d.%d\n", ident.vendor, ident.variant, ident.major, ident.minor);
    
    if (_getHardwareAddress(&macAddr) != kIOReturnSuccess) {
        DBNSLog(@"IntersilJack::_init: Couldn't read MAC address\n");
        return kIOReturnError;
    }
    
    _deviceInit = true;
    
    return kIOReturnSuccess;
}

IOReturn IntersilJack::_reset() {
    int i;
    
    if (_doCommand(wlcInit, 0) != kIOReturnSuccess) {
        DBNSLog(@"IntersilJack::_reset: _doCommand(wlcInit, 0) failed\n");
        return kIOReturnError;
    }
    
    usleep(100000); // give it a sec to reset
    
    for (i = 0; i < wlTimeout; ++i) {
        _firmwareType = _getFirmwareType();
        if (_firmwareType != -1) break;
    }
    
    for (i = 0; i < wlTimeout; ++i) {
        if (_setValue(0xFC00, (_firmwareType == WI_LUCENT) ? 0x3 : 0x5) == kIOReturnSuccess) break;
    }
    
    if (_firmwareType == WI_INTERSIL) {
        _setValue(0xFC06, 1); //syscale
        _setValue(0xFC07, 2304); //max data len
        _setValue(0xFC09, 0); //pm off!
        _setValue(0xFC84, 3); //default tx rate
        _setValue(0xFC85, 0); //promiscous mode
        _setValue(0xFC2A, 1); //auth type
        _setValue(0xFC2D, 1); //roaming by firmware
		_setValue(0xFC28, 0x90); //set wep ignore
		_setValue(0xFC83, 0); //set wep ignore
    }
    
    if (i==wlTimeout) {
        DBNSLog(@"IntersilJack::_reset: could not set port type\n");
        return kIOReturnError;
    }
    
    /*
     * Set list of interesting events
     */
    //_interrupts = wleRx;  //| wleTx | wleTxExc | wleAlloc | wleInfo | wleInfDrop | wleCmd | wleWTErr | wleTick;
    
    _enable();
    _isSending = false;
    
    return kIOReturnSuccess;
}

bool IntersilJack::sendKFrame(KFrame *frame) {
    WLFrame *frameDescriptor;
	UInt8 kmrate;
    UInt8 aData[MAX_FRAME_BYTES];
    IOByteCount pktsize;
    int descriptorLength;
    UInt8 *data = frame->data;
    int size = frame->ctrl.len;
    
    struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)data;
    UInt16 type = (hdr->frame_ctl & IEEE80211_TYPE_MASK);
    UInt16 subtype = (hdr->frame_ctl & IEEE80211_SUBTYPE_MASK);
    UInt16 isToDS = ((hdr->frame_ctl & IEEE80211_DIR_TODS) ? YES : NO);
    UInt16 isFrDS = ((hdr->frame_ctl & IEEE80211_DIR_FROMDS) ? YES : NO);
    UInt16 headerLength = 0;
    
    switch (type) {
        case IEEE80211_TYPE_MGT:
            headerLength = sizeof(struct ieee80211_hdr_3addr);
            break;
        case IEEE80211_TYPE_DATA:
            //            DBNSLog(@"DATA");
            if (subtype == IEEE80211_SUBTYPE_QOS_DATA) {
                //                DBNSLog(@"QOS");
                if (isFrDS && isToDS) {
                    //                    DBNSLog(@"isFrDS && isToDS");
                    headerLength = sizeof(struct ieee80211_hdr_4addrqos); //32
                } else {
                    //                    DBNSLog(@"isFrDS || isToDS");
                    headerLength = sizeof(struct ieee80211_hdr_3addrqos); //26                  
                }
            } else {
                //                DBNSLog(@"NO QOS");
                if (isFrDS && isToDS) {
                    //                    DBNSLog(@"isFrDS && isToDS");
                    headerLength = sizeof(struct ieee80211_hdr_4addr); //30
                } else {
                    //                    DBNSLog(@"isFrDS || isToDS");
                    headerLength = sizeof(struct ieee80211_hdr_3addr); //24               
                }
            }
            break;
            break;
        case IEEE80211_TYPE_CTL:
            break;
    }
    
    frameDescriptor = (WLFrame*)aData;
	kmrate = frame->ctrl.tx_rate;
    descriptorLength = WriteTxDescriptor(frameDescriptor, kmrate);
    DBNSLog(@"descriptorLength = %d", descriptorLength);
	
    // Copy header
    memcpy(aData + sizeof(WLPrismHeader), data, headerLength);
    
    // Copy Data
    if (size <= headerLength) {
        frameDescriptor->dataLen = 0;        
    } else {
        frameDescriptor->dataLen = (size - headerLength);
        memcpy(aData + sizeof(WLFrame), data + headerLength, frameDescriptor->dataLen);        
    }
    
    pktsize = frameDescriptor->dataLen + sizeof(WLFrame);
    frameDescriptor->dataLen = NSSwapHostShortToLittle(frameDescriptor->dataLen);
    
    //send the frame
    if (_sendFrame(aData, pktsize) != kIOReturnSuccess)
        return NO;
    
    return YES;
}

bool IntersilJack::_massagePacket(void *inBuf, void *outBuf, UInt16 len) {
    unsigned char* pData = (unsigned char *)inBuf;
    WLFrame *head = (WLFrame *)pData;
    KFrame *f = (KFrame *)outBuf;

    UInt16 isToDS, isFrDS, subtype, dataLen, headerLength = 0;
    UInt16 type;
//    DBNSLog(@"_massagePacket %d", len);
    if (len < sizeof(WLFrame)) {
        DBNSLog(@"WTF, packet len %d shorter than header %lu!", len, sizeof(WLFrame));
        return false;
    }

    bzero(f,sizeof(KFrame));
    
    // FCS check
    head->status = NSSwapLittleShortToHost(head->status);
    if (head->status & 0x1 || (head->status & 0x700) != 0x700 || head->status & 0xe000) {
        DBNSLog(@"FCS error");
        return false;
    }
    dataLen = NSSwapLittleShortToHost(head->dataLen);
//    DBNSLog(@"dataLen %d", dataLen);
    type = (head->frameControl & IEEE80211_TYPE_MASK);
    subtype = (head->frameControl & IEEE80211_SUBTYPE_MASK);
    isToDS = ((head->frameControl & IEEE80211_DIR_TODS) ? YES : NO);
    isFrDS = ((head->frameControl & IEEE80211_DIR_FROMDS) ? YES : NO);
    switch(type) {
        case IEEE80211_TYPE_MGT:
            DBNSLog(@"MANAGEMENT");
            headerLength = sizeof(struct ieee80211_hdr_3addr);
            break;
        case IEEE80211_TYPE_DATA:
            DBNSLog(@"DATA");
            if (subtype == IEEE80211_SUBTYPE_QOS_DATA) {
//                DBNSLog(@"QOS");
                if (isFrDS && isToDS) {
//                    DBNSLog(@"isFrDS && isToDS");
                    headerLength = sizeof(struct ieee80211_hdr_4addrqos);
                } else {
//                    DBNSLog(@"isFrDS || isToDS");
                    headerLength = sizeof(struct ieee80211_hdr_3addrqos);                    
                }
            } else {
//                DBNSLog(@"NO QOS");
                if (isFrDS && isToDS) {
//                    DBNSLog(@"isFrDS && isToDS");
                    headerLength = sizeof(struct ieee80211_hdr_4addr);
                } else {
//                    DBNSLog(@"isFrDS || isToDS");
                    headerLength = sizeof(struct ieee80211_hdr_3addr);                    
                }
            }
            break;
        case IEEE80211_TYPE_CTL:
            DBNSLog(@"CTL");
            switch(subtype) {
                case IEEE80211_SUBTYPE_PS_POLL:
                case IEEE80211_SUBTYPE_RTS:
                    headerLength=16;
                    break;
                case IEEE80211_SUBTYPE_CTS:
                case IEEE80211_SUBTYPE_ACK:
                    headerLength=10;
                    break;
                default:
                    return false;
                    break;
            }
            break;
        default:
            DBNSLog(@"Unknown frame type %u", type);
            return false;
    }

    memcpy(f->data, pData+sizeof(WLPrismHeader), headerLength);
    if (headerLength >= sizeof(struct ieee80211_hdr_3addr))
        memcpy(f->data + 24, pData+sizeof(WLFrame), dataLen);
    else
        dataLen = 0;
    f->ctrl.len = dataLen+headerLength;
    f->ctrl.signal = head->silence;
    f->ctrl.channel = head->channel;
    f->ctrl.silence = head->signal;
    return true;
}

int IntersilJack::WriteTxDescriptor(WLFrame * theFrame, KMRate kmrate){
	UInt8 rate;
    theFrame->txControl=NSSwapHostShortToLittle(0x08 | _TX_RETRYSTRAT_SET(3)| _TX_CFPOLL_SET(1) | _TX_TXEX_SET(0) | _TX_TXOK_SET(0) | _TX_MACPORT_SET(0));
	switch (kmrate) {
		case KMRate1:
			rate = 0xa;
			break;
		case KMRate2:
			rate = 0x14;
			break;
		case KMRate5_5:
			rate = 0x37;
			break;
		case KMRate11:
			rate = 0x6e;
			break;
		default:
			rate = 0x6e;
			break;
	}
    theFrame->rate = rate;
	theFrame->tx_rate = rate;
    return sizeof(WLPrismHeader);
}

#pragma mark -

IOReturn IntersilJack::_getHardwareAddress(struct WLHardwareAddress* addr) {
    UInt32 size = sizeof(struct WLHardwareAddress);
    
    if (_getRecord(0xFC01, (UInt16*)addr, &size, false) != kIOReturnSuccess) {
        DBNSLog(@"IntersilJack::_getHardwareAddress: getRecord error\n");
        return kIOReturnError;
    }
    
    DBNSLog(@"IntersilJack: MAC 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x\n",
          addr->bytes[0], addr->bytes[1], addr->bytes[2],
          addr->bytes[3], addr->bytes[4], addr->bytes[5]);
    
    return kIOReturnSuccess;
}
IOReturn IntersilJack::_getIdentity(WLIdentity* wli) {
    UInt32 size = sizeof(WLIdentity);
    if (_getRecord(0xFD20, (UInt16*)wli, &size) != kIOReturnSuccess) {
        DBNSLog(@"IntersilJack::getIdentity: getRecord failed\n");
        return kIOReturnError;
    }
    
    return kIOReturnSuccess;
}
int      IntersilJack::_getFirmwareType() {
    UInt16 card_id;
    UInt32 size = 8;
    UInt8 d[8];
    
    if (_getRecord(0xFD0B, (UInt16*)d, &size) != kIOReturnSuccess) {
        DBNSLog(@"IntersilJack::_getFirmwareType: getRecord failed\n");
        return -1;
    }
    
    card_id = *(UInt16*)d;
    if (card_id & 0x8000) {
        DBNSLog(@"IntersilJack: Detected a Prism2 card\n");
        return WI_INTERSIL;
    } else {
        DBNSLog(@"IntersilJack: WARNING detected a Lucent card. This is not supported! 0x%x\n",card_id);
        return WI_LUCENT;
    }
}
IOReturn IntersilJack::_doCommand(enum WLCommandCode cmd, UInt16 param0, UInt16 param1, UInt16 param2) {
    UInt16 status;
    
    if (!_devicePresent) return kIOReturnError;
    
    if (_interface == NULL) {
        DBNSLog(@"IntersilJack::_doCommand called with NULL interface this is prohibited!\n");
        return kIOReturnError;
    }
    
    _lockDevice();
    /* Initialize the command */
    _outputBuffer.cmdreq.type = 	NSSwapHostShortToLittle(_USB_CMDREQ);
    _outputBuffer.cmdreq.cmd =          NSSwapHostShortToLittle(cmd);
    _outputBuffer.cmdreq.parm0 =	NSSwapHostShortToLittle(param0);
    _outputBuffer.cmdreq.parm1 =	NSSwapHostShortToLittle(param1);
    _outputBuffer.cmdreq.parm2 =	NSSwapHostShortToLittle(param2);
    
    if (_writeWaitForResponse(sizeof(_outputBuffer.cmdreq)) != kIOReturnSuccess) {
        DBNSLog(@"IntersilJack::unable to execute commmand (%08x)\n", cmd);
        _unlockDevice();
        return kIOReturnError;
    }
    
    status = NSSwapLittleShortToHost(_inputBuffer.cmdresp.status) >> 7;
    _unlockDevice();
    
    if (status) {
        DBNSLog(@"IntersilJack::_doCommand: Status code (0x%x) at command cmd 0x%x\n", status, cmd);
        return kIOReturnError;
    }
    
    return kIOReturnSuccess;
}
IOReturn IntersilJack::_doCommandNoWait(enum WLCommandCode cmd, UInt16 param0, UInt16 param1, UInt16 param2) {
    IOReturn kr;
    
    if (_interface == NULL) {
        DBNSLog(@"IntersilJack::_doCommandNoWait called with NULL interface this is prohibited!\n");
        return kIOReturnError;
    }
    
    _lockDevice();
    /* Initialize the command */
    _outputBuffer.cmdreq.type  = 	NSSwapHostShortToLittle(_USB_CMDREQ);
    _outputBuffer.cmdreq.cmd   =    NSSwapHostShortToLittle(cmd);
    _outputBuffer.cmdreq.parm0 =	NSSwapHostShortToLittle(param0);
    _outputBuffer.cmdreq.parm1 =	NSSwapHostShortToLittle(param1);
    _outputBuffer.cmdreq.parm2 =	NSSwapHostShortToLittle(param2);
    
    kr = (*_interface)->WritePipe(_interface, kOutPipe, &_outputBuffer, sizeof(_outputBuffer.cmdreq));
    _unlockDevice();
    
    return kr;
}
IOReturn IntersilJack::_getRecord(UInt16 rid, void* buf, UInt32* n, bool swapBytes) {
    UInt32  readLength = 0;
    
    if (!_devicePresent) return kIOReturnError;
    
    if (_interface == NULL) {
        DBNSLog(@"IntersilJack::_getRecord called with NULL interface this is prohibited!\n");
        return kIOReturnError;
    }
    
    _lockDevice();
    
    _outputBuffer.rridreq.type =   NSSwapHostShortToLittle(_USB_RRIDREQ);
    _outputBuffer.rridreq.frmlen = NSSwapHostShortToLittle(sizeof(_outputBuffer.rridreq.rid));
    _outputBuffer.rridreq.rid =    NSSwapHostShortToLittle(rid);
    
    if (_writeWaitForResponse(sizeof(_outputBuffer.rridreq)) != kIOReturnSuccess) {
        DBNSLog(@"IntersilJack::unable to write record offset.\n");
        _unlockDevice();
        return kIOReturnError;
    }
    
    readLength = ((NSSwapLittleShortToHost(_inputBuffer.rridresp.frmlen)-1)*2);
    if (readLength != *n) {  
        //DBNSLog(@"IntersilJack::RID len mismatch, rid=0x%04x hlen=%d fwlen=%d\n", rid, *n, readLength);
        _unlockDevice();
        return kIOReturnError;
    }
    
    if (swapBytes) {
        swab(_inputBuffer.rridresp.data, buf, readLength);
    } else {
        memcpy(buf, _inputBuffer.rridresp.data, readLength);
    }
    
    _unlockDevice();
    
    return kIOReturnSuccess;
}
IOReturn IntersilJack::_setRecord(UInt16 rid, const void* buf, UInt32 n, bool swapBytes) {
    UInt32      numBytes;
    UInt16      status;
    
    if (!_devicePresent) return kIOReturnError;
    
    if (_interface == NULL) {
        DBNSLog(@"IntersilJack::_setRecord called with NULL interface this is prohibited!\n");
        return kIOReturnError;
    }
    
    _lockDevice();
    
    bzero(&_outputBuffer, sizeof(_outputBuffer));
    _outputBuffer.wridreq.type =   NSSwapHostShortToLittle(_USB_WRIDREQ);
    _outputBuffer.wridreq.frmlen = NSSwapHostShortToLittle((sizeof(_outputBuffer.wridreq.rid) + n + 1) / 2);
    _outputBuffer.wridreq.rid =    NSSwapHostShortToLittle(rid);
    
    if (swapBytes) {
        swab(buf, _outputBuffer.wridreq.data, n);
    } else {
        memcpy(_outputBuffer.wridreq.data, buf, n);
    }
    
    numBytes =  align64(sizeof(_outputBuffer.wridreq.type) +
                        sizeof(_outputBuffer.wridreq.frmlen) + sizeof(_outputBuffer.wridreq.rid) + n);
    
    if (_writeWaitForResponse(numBytes) != kIOReturnSuccess) {
        DBNSLog(@"IntersilJack::unable to write record offset for writing.\n");
        _unlockDevice();
        return kIOReturnError;
    }
    
    status = NSSwapLittleShortToHost(_inputBuffer.wridresp.status);
    if (status & 0x7F00) {
        DBNSLog(@"IntersilJack::_setRecord: setRecord result 0x%x\n", status & 0x7F00);
        _unlockDevice();
        return kIOReturnError;
    }
    
    _unlockDevice();
    
    return kIOReturnSuccess;
}
IOReturn IntersilJack::_getValue(UInt16 rid, UInt16* v) {
    UInt32 n = 2;
    return _getRecord(rid, v, &n);
}
IOReturn IntersilJack::_setValue(UInt16 rid, UInt16 v) {
    UInt16 value = v;
    IOReturn ret = _setRecord(rid, &value, 2);
    
    if (ret != kIOReturnSuccess)
        return ret;
    
    ret = _getValue(rid, &value);
    
    if (ret != kIOReturnSuccess)
        return ret;
    
    if (value != v) {
        //DBNSLog(@"IntersilJack::setValue: Failed to set value (0x%x != 0x%x) for register 0x%x\n", value, v, rid);
        return kIOReturnError;
    }
    
    return kIOReturnSuccess;
}
IOReturn IntersilJack::_writeWaitForResponse(UInt32 size) {
    IOReturn kr;
    struct timespec to;
    int error;
    int calls = 0;
    
    to.tv_nsec = 0;
    
    do {
        kr = (*_interface)->WritePipe(_interface, kOutPipe, &_outputBuffer, size);
        if (kr != kIOReturnSuccess) {
            if (kr==wlcDeviceGone) _devicePresent = false;
            else DBNSLog(@"IntersilJack::unable to write to USB Device(%08x)\n", kr);
            return kr;
        }
        
        to.tv_sec  = time(0) + 5;
        error = pthread_cond_timedwait(&_wait_cond, &_wait_mutex, &to);
        if (error == ETIMEDOUT) DBNSLog(@"Timeout error.");
        
        if (calls++ == 5) return kIOReturnTimeout;
    } while (error == ETIMEDOUT); //wait for async response
    
    return kIOReturnSuccess;
}
IOReturn IntersilJack::_enable() {
    if (_doCommand(wlcEnable, 0) != kIOReturnSuccess) {
        DBNSLog(@"IntersilJack::startCapture: _doCommand(wlcEnable) failed\n");
        return kIOReturnError;
    }
    _isEnabled = true;
    
    return kIOReturnSuccess;
}
IOReturn IntersilJack::_disable() {
    if (_doCommand(wlcDisable, 0) != kIOReturnSuccess) {
        DBNSLog(@"IntersilJack::_disable: _doCommand(wlcDisable) failed\n");
        return kIOReturnError;
    }
    _isEnabled = false;
    
    return kIOReturnSuccess;
}


IntersilJack::IntersilJack() {
    pthread_mutex_init(&_wait_mutex, NULL);
    pthread_cond_init (&_wait_cond, NULL);
}

IntersilJack::~IntersilJack() {
/*
    stopRun();
    _interface = NULL;
    
    pthread_mutex_destroy(&_wait_mutex);
    pthread_cond_destroy(&_wait_cond);
    pthread_mutex_destroy(&_recv_mutex);
    pthread_cond_destroy(&_recv_cond);
*/
}

