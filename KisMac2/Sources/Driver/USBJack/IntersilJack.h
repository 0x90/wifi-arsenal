//
//  IntersilJack.h
//  KisMAC
//
//  Created by Geoffrey Kruse on 5/1/06.
//  Copyright 2006 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "KMCommon.h"
#import "USBJack.h"

class IntersilJack: public USBJack
{
public:

    IntersilJack();
    ~IntersilJack();
    
    IOReturn    _init();
    IOReturn    _reset();
    
    char   *getPlistFile();
    bool    startCapture(UInt16 channel);
    bool    stopCapture();
    bool    getChannel(UInt16* channel);
    bool    getAllowedChannels(UInt16* channel);
    bool    setChannel(UInt16 channel);
    int     WriteTxDescriptor(WLFrame * theFrame, KMRate kmrate);
    bool    sendKFrame(KFrame *frame);
    bool    _massagePacket(void *inBuf, void *outBuf, UInt16 len);
    
    IOReturn    _doCommand(enum WLCommandCode cmd, UInt16 param0, UInt16 param1 = 0, UInt16 param2 = 0);
    IOReturn    _doCommandNoWait(enum WLCommandCode cmd, UInt16 param0, UInt16 param1 = 0, UInt16 param2 = 0);

#if BYTE_ORDER == BIG_ENDIAN
    IOReturn    _getRecord(UInt16 rid, void* buf, UInt32* n, bool swapBytes = true);
    IOReturn    _setRecord(UInt16 rid, const void* buf, UInt32 n, bool swapBytes = true);
#else 
    IOReturn    _getRecord(UInt16 rid, void* buf, UInt32* n, bool swapBytes = false); 
    IOReturn    _setRecord(UInt16 rid, const void* buf, UInt32 n, bool swapBytes = false); 
#endif

    IOReturn    _getValue(UInt16 rid, UInt16* v);
    IOReturn    _setValue(UInt16 rid, UInt16 v);
    IOReturn    _writeWaitForResponse(UInt32 size);
    IOReturn    _getHardwareAddress(struct WLHardwareAddress* addr);
    IOReturn    _getIdentity(WLIdentity* wli);
    int         _getFirmwareType();
    IOReturn    _disable();
    IOReturn    _enable();
    
private:
        //int temp;
};


