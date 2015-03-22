/*
        
        File:			USBIntersil.mm
        Program:		KisMAC
		Author:			Michael Rossberg
						mick@binaervarianz.de
		Description:	KisMAC is a wireless stumbler for MacOS X.
                
        This file is part of KisMAC.

    KisMAC is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License, version 2,
    as published by the Free Software Foundation;

    KisMAC is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with KisMAC; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/
	
#include <IOKit/IOKitLib.h>
#include <IOKit/IOCFPlugIn.h>

#include "USBJack.h"

#define align64(a)      (((a)+63)&~63)  

#define dbgOutPutBuf(a) DBNSLog( @"0x%.4x 0x%.4x 0x%.4x 0x%.4x%.4x", NSSwapLittleShortToHost(*((UInt16*)&(a) )), NSSwapLittleShortToHost(*((UInt16*)&(a)+1)), NSSwapLittleShortToHost(*((UInt16*)&(a)+2)), NSSwapLittleShortToHost(*((UInt16*)&(a)+3)), NSSwapLittleShortToHost(*((UInt16*)&(a)+4)) );              

#import <mach/mach_types.h>
#import <mach/mach_error.h>

#pragma mark -

USBJack::USBJack() {
    _isEnabled = false;
    _deviceInit = false;
    _devicePresent = false;
    _deviceMatched = false;

    _interface = NULL;
    _runLoopSource = NULL;
    _runLoop = NULL;
    _channel = 3;
    _notifyPort = NULL;
    
    _numDevices = -1;
    _frameRing = NULL;
    
    // Initialize internal frame queue
    initFrameQueue();
    
    pthread_mutex_init(&_wait_mutex, NULL);
    pthread_cond_init (&_wait_cond, NULL);

    // Start loop
    run();
    
    while (_runLoop == NULL)
        usleep(100);
}

USBJack::~USBJack() {
    // Stop
    stopRun();
    
    _interface = NULL;
    _matchingDone = false;

    // Destroy frame queue
    destroyFrameQueue();
    
    pthread_mutex_destroy(&_wait_mutex);
    pthread_cond_destroy(&_wait_cond);
}

bool USBJack::loadPropertyList()
{
    CFStringRef ref;
    CFStringRef plistFile = CFStringCreateWithCString(kCFAllocatorDefault, getPlistFile(), kCFStringEncodingASCII);
    CFURLRef url = CFBundleCopyResourceURL(CFBundleGetMainBundle(), plistFile, CFSTR("plist"), NULL);
	CFRelease(plistFile);
    if (url == NULL)
    {
        return false;
    }
    
    NSData *data = [NSData dataWithContentsOfURL:(__bridge NSURL *)url
                                          options:NSMappedRead
                                            error:nil];
    
	CFRelease(url);
    _vendorsPlist = CFPropertyListCreateFromXMLData(kCFAllocatorDefault, (__bridge CFDataRef)(data), kCFPropertyListImmutable, &ref);
    if (CFDictionaryGetTypeID() != CFGetTypeID(_vendorsPlist))
    {
        return false;
    }

	return true;
}
IOReturn USBJack::_init() {
    return kIOReturnError;  //this method MUST be overridden
}

bool USBJack::getChannel(UInt16* channel) {
    *channel = _channel;
    return true;   //this method MUST be overridden
}
bool USBJack::setChannel(UInt16 channel) {
    return false;   //this method MUST be overridden
}

bool USBJack::startCapture(UInt16 channel) {
    return false;   //this method MUST be overridden
}
bool USBJack::stopCapture() {
    return false;   //this method MUST be overridden
}

void USBJack::startMatching()
{
    mach_port_t 		masterPort;
    CFMutableDictionaryRef 	matchingDict;
    kern_return_t		kr;
    
    // Checks if we already have matched
    if (_runLoopSource || _matchingDone)
        return;

    // Load property list
    loadPropertyList();
    
    _matchingDone = true;
    _deviceMatched = false;
    _numDevices = -1;
    
    // first create a master_port for my task
    kr = IOMasterPort(MACH_PORT_NULL, &masterPort);
    if (kr || !masterPort) {
        DBNSLog(@"ERR: Couldn't create a master IOKit Port(%08x)\n", kr);
        return;
    }
    
    // Set up the matching criteria for the devices we're interested in
    matchingDict = IOServiceMatching(kIOUSBDeviceClassName);	// Interested in instances of class IOUSBDevice and its subclasses
    if (!matchingDict) {
        DBNSLog(@"Can't create a USB matching dictionary\n");
        //mach_port_deallocate(mach_task_self(), masterPort);
        return;
    }
    
    // Create a notification port and add its run loop event source to our run loop
    // This is how async notifications get set up.
    _notifyPort = IONotificationPortCreate(masterPort);
    _runLoopSource = IONotificationPortGetRunLoopSource(_notifyPort);
    
    CFRunLoopAddSource(_runLoop, _runLoopSource, kCFRunLoopDefaultMode);
    
    // Retain additional references because we use this same dictionary with four calls to 
    // IOServiceAddMatchingNotification, each of which consumes one reference.
    matchingDict = (CFMutableDictionaryRef) CFRetain(matchingDict); 
    
    // Now set up two more notifications, one to be called when a bulk test device is first matched by I/O Kit, and the other to be
    // called when the device is terminated.
    kr = IOServiceAddMatchingNotification(_notifyPort,
                                          kIOFirstMatchNotification,
                                          matchingDict,
                                          _addDevice,
                                          this,
                                          &_deviceAddedIter);
    
	if (kIOReturnSuccess != kr) {
		DBNSLog(@"unable to Add Matching Notification (%08x)\n", kr);
	}

    _addDevice(this, _deviceAddedIter);	// Iterate once to get already-present devices and
    // arm the notification
    
    kr = IOServiceAddMatchingNotification(  _notifyPort,
                                          kIOTerminatedNotification,
                                          matchingDict,
                                          _handleDeviceRemoval,
                                          this,
                                          &_deviceRemovedIter );
    
    _handleDeviceRemoval(this, _deviceRemovedIter); 	// Iterate once to arm the notification
    
	if (kIOReturnSuccess != kr) {
		DBNSLog(@"unable to handle Device Removal (%08x)\n", kr);
	}
    
    // Now done with the master_port
    masterPort = 0;
}

KFrame *USBJack::receiveFrame()
{
    UInt16 len = 0, channel = 0;
    KFrame *ret = (KFrame *)&_frameBuffer;
    void *receivedFrame;
    
    if (!_devicePresent)
    {
        return NULL;
    }
    
    while (1)
    {
        receivedFrame = getFrameFromQueue(&len, &channel);
        if (receivedFrame)
        {
            if(!_massagePacket(receivedFrame, (void *)&_frameBuffer, len))
                continue;
            ret->ctrl.channel = channel;
            return ret;
        }
        else 
        {
            return NULL;
        }
    }
}

bool USBJack::sendKFrame(KFrame *data) {
    // Override in subclasses
    return NO;
}

bool USBJack::getAllowedChannels(UInt16* channels) {
    return false;   //this method MUST be overridden
}


bool USBJack::devicePresent() {
    return _devicePresent;
}
bool USBJack::deviceMatched() {
    return _deviceMatched;
}

#pragma mark -

#pragma mark -

IOReturn USBJack::_reset() {
    return kIOReturnError;  //this method MUST be overridden
}

#pragma mark -

IOReturn USBJack::_sendFrame(UInt8* data, IOByteCount size) {
    UInt32      numBytes;
    IOReturn    kr;
    
    if (!_devicePresent) return kIOReturnError;
    
    if (_interface == NULL) {
        DBNSLog(@"USBJack::_sendFrame called with NULL interface this is prohibited!\n");
        return kIOReturnError;
    }
    
    _lockDevice();

    memcpy(&_outputBuffer, data, size);
    
    //not sure about this
    _outputBuffer.type =   NSSwapHostShortToLittle(_USB_TXFRM);
    
    numBytes =  align64(size);

    kr = (*_interface)->WritePipe(_interface, kOutPipe, &_outputBuffer, numBytes);
    
    _unlockDevice();
        
    return kr;
}

#pragma mark -

void  USBJack::_lockDevice() {
    pthread_mutex_lock(&_wait_mutex);
}
void  USBJack::_unlockDevice() {
    pthread_mutex_unlock(&_wait_mutex);
}
void USBJack::_interruptReceived(void *refCon, IOReturn result, unsigned int len)
{
    USBJack             *me = (USBJack*) refCon;
    IOReturn                    kr;
    UInt32                      type;

//    DBNSLog(@"Interrupt Received %d", len);
    KFrame *frame;
	bool needBreakProcess = false;
	
    if (kIOReturnSuccess != result) {
        if (result == (IOReturn)0xe00002ed)
		{
            me->_devicePresent = false;
            
            //tell the receive function that we are gone
            me->insertFrameIntoQueue(NULL, 0, 0);
			
            return;
        }
		else
		{
            DBNSLog(@"error from async interruptReceived (%08x)\n", result);
            if (me->_devicePresent)
			{
				needBreakProcess = true;
			}
        }
    }
    
	if (!needBreakProcess)
	{
		type = NSSwapLittleShortToHost(me->_receiveBuffer.type);
		if (_USB_ISRXFRM(type))
		{
			if (len <= sizeof(KFrame))
			{
				// Get raw data pointer
				frame = (KFrame*)&(me->_receiveBuffer.rxfrm);
				
				// Here we insert raw data frame into queue because we need to do things
				// as fast as possible. Remember that we are servicing an interrupt.
				// Custom conversion will be done on dequeuing
				
				// Lock for copying frame
				me->insertFrameIntoQueue(frame, len, me->_channel);
			}
		}
		else
		{
			switch (type)
			{
				case _USB_CMDRESP:
				case _USB_WRIDRESP:
				case _USB_RRIDRESP:
				case _USB_WMEMRESP:
				case _USB_RMEMRESP:
					pthread_mutex_lock(&me->_wait_mutex);
					memcpy(&me->_inputBuffer, &me->_receiveBuffer, len);
					pthread_cond_signal(&me->_wait_cond);
					pthread_mutex_unlock(&me->_wait_mutex);
					break;
				case _USB_BUFAVAIL:
					DBNSLog(@"Received BUFAVAIL packet, frmlen=%d\n", me->_receiveBuffer.bufavail.frmlen);
					break;
				case _USB_ERROR:
					DBNSLog(@"Received USB_ERROR packet, errortype=%d\n", me->_receiveBuffer.usberror.errortype);
					break;
				case _USB_INFOFRM:
				default:
					break;
			}
		}
	}
    
    bzero(&me->_receiveBuffer, sizeof(me->_receiveBuffer));
    kr = (*me->_interface)->ReadPipeAsync((me->_interface), (me->kInPipe), &me->_receiveBuffer, sizeof(me->_receiveBuffer), (IOAsyncCallback1)_interruptReceived, refCon);
	
    if (kIOReturnSuccess != kr)
	{
        DBNSLog(@"unable to do async interrupt read (%08x). this means the card is stopped!\n", kr);
		// I haven't been able to reproduce the error that caused it to hit this point in the code again since adding the following lines
		// however, when it hit this point previously, the only solution was to kill and relaunch KisMAC, so at least this won't make anything worse
		DBNSLog(@"Attempting to re-initialise adapter...");
		
		if (me->_init() != kIOReturnSuccess)
		{
			DBNSLog(@"USBJack::_interruptReceived: _init() failed\n");
		}
    }
        
}
bool USBJack::_massagePacket(void *inBuf, void *outBuf, UInt16 len){
    return true;         //override if needed
}

# pragma mark -
# pragma mark Internal Packet Queue
# pragma mark -

int USBJack::initFrameQueue(void) {
    _frameRing = (struct __frameRing *)calloc(1, sizeof(struct __frameRing));
    memset(_frameRing, 0, sizeof(struct __frameRing));
    return 0;
}
int USBJack::destroyFrameQueue(void) {
    free(_frameRing);
    return 0;
}
int USBJack::insertFrameIntoQueue(KFrame *f, UInt16 len, UInt16 channel)  {
    struct __frameRingSlot *slot = nil;
    
    if(_frameRing)
    {
        slot = &(_frameRing->slots[_frameRing->writeIdx]);
    
        _frameRing->received++;
        #if 0
            if (_frameRing->received % 1000 == 0)
                DBNSLog(@"Received %d", _frameRing->received);
        #endif
        if (slot->state == FRAME_SLOT_USED) 
        {
            //        DBNSLog(@"Dropped packet, ring full");
            _frameRing->dropped++;
            if (_frameRing->dropped % 100 == 0)
                DBNSLog(@"Dropped %d", _frameRing->dropped);
            return 0;
        }
        //make sure f exists, otherwise we crash and burn
        if(f)
        {
            memcpy(&(slot->frame), f, sizeof(KFrame));
        }
        slot->len = len;
        slot->channel = channel;
        slot->state = FRAME_SLOT_USED;
        _frameRing->writeIdx = (_frameRing->writeIdx + 1) % RING_SLOT_NUM;
    }
    return 0;
}
KFrame *USBJack::getFrameFromQueue(UInt16 *len, UInt16 *channel) {
    static KFrame f;
    struct __frameRingSlot *slot = nil;
    
    if(_frameRing)
    {
        slot = &(_frameRing->slots[_frameRing->readIdx]);

        //    DBNSLog(@"Slot %p readIdx %d", slot, _frameRing->readIdx);
        if(!slot) return nil;

        while (slot->state == FRAME_SLOT_FREE)
            usleep(10000);

        //we must return nil if a frame has zero length.
        //note returning nil generally indicates that the driver has faild :(
        if(0 == slot->len)
        {
            return nil;
        }
        else //copy it for return
        {
            memcpy(&f, &(slot->frame), sizeof(KFrame));
            (*len) = slot->len;
            (*channel) = slot->channel;
            slot->state = FRAME_SLOT_FREE;
            _frameRing->readIdx = (_frameRing->readIdx + 1) % RING_SLOT_NUM;
        }
    }
    return &f;
}

#pragma mark -

IOReturn USBJack::_configureAnchorDevice(IOUSBDeviceInterface197 **dev) {
    UInt8				numConf;
    IOReturn				kr;
    IOUSBConfigurationDescriptorPtr	confDesc;
    kr = (*dev)->GetNumberOfConfigurations(dev, &numConf);
	if (kIOReturnSuccess != kr) {
		DBNSLog(@"unable to Get Number Of Configurations (%08x)\n", kr);
	}
	
    DBNSLog(@"Number of configs found: %d\n", numConf);
    if (!numConf)
        return kIOReturnError;
    
    // get the configuration descriptor for index 0
    kr = (*dev)->GetConfigurationDescriptorPtr(dev, 0, &confDesc);
    if (kr) {
        DBNSLog(@"\tunable to get config descriptor for index %d (err = %08x)\n", 0, kr);
        return kIOReturnError;
    }
    kr = (*dev)->SetConfiguration(dev, confDesc->bConfigurationValue);
    if (kr) {
        DBNSLog(@"\tunable to set configuration to value %d (err=%08x)\n", 0, kr);
            return kIOReturnError;
    }
    return kIOReturnSuccess;
}
IOReturn USBJack::_findInterfaces(IOUSBDeviceInterface197 **dev) {
    IOReturn			kr;
    IOUSBFindInterfaceRequest	request;
    io_iterator_t		iterator;
    io_service_t		usbInterface;
    IOCFPlugInInterface 	**plugInInterface = NULL;
    IOUSBInterfaceInterface220 	**intf = NULL;
    HRESULT 			res;
    SInt32 			score;
    UInt8			intfClass;
    UInt8			intfSubClass;
    UInt8			intfNumEndpoints;
    int				pipeRef;
    CFRunLoopSourceRef		runLoopSource;
    BOOL                        error;
    
    
    request.bInterfaceClass = kIOUSBFindInterfaceDontCare;
    request.bInterfaceSubClass = kIOUSBFindInterfaceDontCare;
    request.bInterfaceProtocol = kIOUSBFindInterfaceDontCare;
    request.bAlternateSetting = kIOUSBFindInterfaceDontCare;
   
    kr = (*dev)->CreateInterfaceIterator(dev, &request, &iterator);
    
    while ((usbInterface = IOIteratorNext(iterator))) {
        DBNSLog(@"Interface found.\n");
       
        kr = IOCreatePlugInInterfaceForService(usbInterface, kIOUSBInterfaceUserClientTypeID, kIOCFPlugInInterfaceID, &plugInInterface, &score);
		if (kIOReturnSuccess != kr) {
			DBNSLog(@"unable to Create Plug In Interface For Service (%08x)\n", kr);
		}
        kr = IOObjectRelease(usbInterface);				// done with the usbInterface object now that I have the plugin
        if ((kIOReturnSuccess != kr) || !plugInInterface) {
            DBNSLog(@"unable to create a plugin (%08x)\n", kr);
            break;
        }
            
        // I have the interface plugin. I need the interface interface
        res = (*plugInInterface)->QueryInterface(plugInInterface, CFUUIDGetUUIDBytes(kIOUSBInterfaceInterfaceID220), (void**) &intf);
        (*plugInInterface)->Release(plugInInterface);			// done with this
        if (res || !intf) {
            DBNSLog(@"couldn't create an IOUSBInterfaceInterface (%08x)\n", (int) res);
            break;
        }
        
        kr = (*intf)->GetInterfaceClass(intf, &intfClass);
		if (kIOReturnSuccess != kr) {
			DBNSLog(@"unable to Get Interface Class (%08x)\n", kr);
		}
        kr = (*intf)->GetInterfaceSubClass(intf, &intfSubClass);
        if (kIOReturnSuccess != kr) {
			DBNSLog(@"unable to Get Interface Sub Class (%08x)\n", kr);
		}
        //DBNSLog(@"Interface class %d, subclass %d\n", intfClass, intfSubClass);
        
        // Now open the interface. This will cause the pipes to be instantiated that are 
        // associated with the endpoints defined in the interface descriptor.
        kr = (*intf)->USBInterfaceOpen(intf);
        if (kIOReturnSuccess != kr) {
            DBNSLog(@"unable to open interface (%08x)\n", kr);
            (void) (*intf)->Release(intf);
            break;
        }
        
    	kr = (*intf)->GetNumEndpoints(intf, &intfNumEndpoints);
        if (kIOReturnSuccess != kr) {
            DBNSLog(@"unable to get number of endpoints (%08x)\n", kr);
            (void) (*intf)->USBInterfaceClose(intf);
            (void) (*intf)->Release(intf);
            break;
        }
        
        if (intfNumEndpoints < 1) {
            DBNSLog(@"Error: Interface has %d endpoints. Needs at least one!!\n", intfNumEndpoints);
            (void) (*intf)->USBInterfaceClose(intf);
            (void) (*intf)->Release(intf);
            break;
        }
        
        for (pipeRef = 1; pipeRef <= intfNumEndpoints; ++pipeRef)
        {
            IOReturn	kr2;
            UInt8	direction;
            UInt8	number;
            UInt8	transferType;
            UInt16	maxPacketSize;
            UInt8	interval;
            
            kr2 = (*intf)->GetPipeProperties(intf, pipeRef, &direction, &number, &transferType, &maxPacketSize, &interval);
            if (kIOReturnSuccess != kr) {
                DBNSLog(@"unable to get properties of pipe %d (%08x)\n", pipeRef, kr2);
                (void) (*intf)->USBInterfaceClose(intf);
                (void) (*intf)->Release(intf);
                break;
            } else {
                DBNSLog(@"%d %d", pipeRef, direction);
                error = false;
                if (direction == kUSBIn && transferType == kUSBBulk) kInPipe = pipeRef;
                else if (direction == kUSBOut && transferType == kUSBBulk) kOutPipe = pipeRef;
                else if (direction == kUSBIn && transferType  == kUSBInterrupt) kInterruptPipe = pipeRef;
                else DBNSLog(@"Found unknown interface, ignoring");
            
                if (error) {
                    DBNSLog(@"unable to properties of pipe %d are not as expected!\n", pipeRef);
                    (void) (*intf)->USBInterfaceClose(intf);
                    (void) (*intf)->Release(intf);
                    break;
                }
            }
        }
        
        // Just like with service matching notifications, we need to create an event source and add it 
        //  to our run loop in order to receive async completion notifications.
        kr = (*intf)->CreateInterfaceAsyncEventSource(intf, &runLoopSource);
        if (kIOReturnSuccess != kr) {
            DBNSLog(@"unable to create async event source (%08x)\n", kr);
            (void) (*intf)->USBInterfaceClose(intf);
            (void) (*intf)->Release(intf);
            break;
        }
        CFRunLoopAddSource(_runLoop, runLoopSource, kCFRunLoopDefaultMode);
        
        _interface = intf;
        
        DBNSLog(@"USBJack is now ready to start working.\n");
        
        //startUp Interrupt handling
        UInt32 numBytesRead = sizeof(_receiveBuffer); // leave one byte at the end for NUL termination
        bzero(&_receiveBuffer, numBytesRead);
        kr = (*intf)->ReadPipeAsync(intf, kInPipe, &_receiveBuffer, numBytesRead, (IOAsyncCallback1)_interruptReceived, this);
        
        if (kIOReturnSuccess != kr) {
            DBNSLog(@"unable to do async interrupt read (%08x)\n", kr);
            (void) (*intf)->USBInterfaceClose(intf);
            (void) (*intf)->Release(intf);
            break;
        }
        
        _devicePresent = true;
        
        if (_channel) {
            startCapture(_channel);
        }
        
        break;
    }
    
    return kr;
}
bool USBJack::_attachDevice() {
    kern_return_t		kr;
    IOUSBDeviceInterface197    **dev;
    
    if ((dev = _foundDevices[_numDevices--])) {
        
        // need to open the device in order to change its state
        kr = (*dev)->USBDeviceOpen(dev);
        if (kIOReturnSuccess != kr) {
            if (kr == kIOReturnExclusiveAccess) {
                DBNSLog(@"Device already in use.");
            }
            else {
                DBNSLog(@"unable to open device: %08x\n", kr);
            }
            (*dev)->Release(dev);
            return false;
        }
        
        kr = _configureAnchorDevice(dev);
        if (kIOReturnSuccess != kr) {
            DBNSLog(@"unable to configure device: %08x\n", kr);
            (*dev)->USBDeviceClose(dev);
            (*dev)->Release(dev);
            return false;
        }
        
        kr = _findInterfaces(dev);
        if (kIOReturnSuccess != kr) {
            DBNSLog(@"unable to find interfaces on device: %08x\n", kr);
            (*dev)->USBDeviceClose(dev);
            (*dev)->Release(dev);
            return false;
        }
        
        kr = (*dev)->USBDeviceClose(dev);
		if (kIOReturnSuccess != kr) {
			DBNSLog(@"unable to USB Device Close (%08x)\n", kr);
		}
        kr = (*dev)->Release(dev);
		if (kIOReturnSuccess != kr) {
			DBNSLog(@"unable to Release (%08x)\n", kr);
		}
    
    }
    return true;
}
void USBJack::_addDevice(void *refCon, io_iterator_t iterator) {
    kern_return_t		kr;
    io_service_t		usbDevice;
    IOCFPlugInInterface 	**plugInInterface=NULL;
    IOUSBDeviceInterface197    **dev=NULL;
    HRESULT 			res;
    SInt32 			score;
    
    UInt16			vendor;
    UInt16			product;
    UInt16			release;
    USBJack     *me = (USBJack*)refCon;

    
    while ((usbDevice = IOIteratorNext(iterator))) {
        //DBNSLog(@"USB Device added.\n");
       
        kr = IOCreatePlugInInterfaceForService(usbDevice, kIOUSBDeviceUserClientTypeID, kIOCFPlugInInterfaceID, &plugInInterface, &score);
        if ((kIOReturnSuccess != kr) || !plugInInterface) {
            kr = IOObjectRelease(usbDevice);				// done with the device object now that I have the plugin
            DBNSLog(@"unable to create a plugin (%08x)\n", kr);
            continue;
        }
        kr = IOObjectRelease(usbDevice);				// done with the device object now that I have the plugin
		if (kIOReturnSuccess != kr) {
			DBNSLog(@"unable to IOObjectRelease (%08x)\n", kr);
		}
        // I have the device plugin, I need the device interface
        res = (*plugInInterface)->QueryInterface(plugInInterface, CFUUIDGetUUIDBytes(kIOUSBDeviceInterfaceID197), (void**)&dev);
        (*plugInInterface)->Release(plugInInterface);			// done with this
        if (res || !dev) {
            DBNSLog(@"couldn't create a device interface (%08x)\n", (int) res);
            continue;
        }
        // technically should check these kr values
        kr = (*dev)->GetDeviceVendor(dev, &vendor);
		if (kIOReturnSuccess != kr) {
			DBNSLog(@"unable to GetDeviceVendor (%08x)\n", kr);
		}
        kr = (*dev)->GetDeviceProduct(dev, &product);
		if (kIOReturnSuccess != kr) {
			DBNSLog(@"unable to GetDeviceProduct (%08x)\n", kr);
		}
        kr = (*dev)->GetDeviceReleaseNumber(dev, &release);
		if (kIOReturnSuccess != kr) {
			DBNSLog(@"unable to GetDeviceReleaseNumber (%08x)\n", kr);
		}
        
        CFTypeRef *keys, *values, n;
        CFIndex count, i;
        UInt16 productId, vendorId;
        CFIndex length;
        char *modelStr;
        
        count = CFDictionaryGetCount( (CFDictionaryRef) (me->_vendorsPlist) );
        keys = (const void **) malloc(count * sizeof(CFTypeRef));
        values = (const void **) malloc(count * sizeof(CFTypeRef));
        
        CFDictionaryGetKeysAndValues( (CFDictionaryRef) (me->_vendorsPlist) , keys, values);
        DBNSLog(@"---");
        for (i=0;i<count;++i) {
            n = CFDictionaryGetValue((CFDictionaryRef)values[i], CFSTR("idProduct"));
            CFNumberGetValue((CFNumberRef)n, kCFNumberSInt16Type, &productId);
            n = CFDictionaryGetValue((CFDictionaryRef)values[i], CFSTR("idVendor"));
            CFNumberGetValue((CFNumberRef)n, kCFNumberSInt16Type, &vendorId);
            DBNSLog(@"vendor %d vendorId %d product %d productId %d", vendor, vendorId, product, productId);
            if ((vendor == vendorId) && (product == productId)) {
                length = CFStringGetMaximumSizeForEncoding(CFStringGetLength((CFStringRef)keys[i]), kCFStringEncodingASCII) + 1;
                modelStr = (char *)malloc(length);
                CFStringGetCString((CFStringRef)keys[i], modelStr, length, kCFStringEncodingASCII);
                DBNSLog(@"USB Device found (%s)", modelStr);
                free(modelStr);
                me->_foundDevices[++me->_numDevices] = dev;
                me->_deviceMatched = true;
                break;
            }
        }
        
        free(keys);
        free(values);
        
        if (!me->_deviceMatched)
            (*dev)->Release(dev);
    }
}

void USBJack::_handleDeviceRemoval(void *refCon, io_iterator_t iterator)
{
    kern_return_t	kr;
    io_service_t	obj;
    int                 count = 0;
    USBJack     *me = (USBJack*)refCon;
    
    while ((obj = IOIteratorNext(iterator)))
    {
        ++count;
        //we need to not release devices that don't belong to us!?
        DBNSLog(@"USBJack: Device removed.\n");
        kr = IOObjectRelease(obj);
		if (kIOReturnSuccess != kr) {
			DBNSLog(@"unable to IOObjectRelease (%08x)\n", kr);
		}
    }
    
    if (count) 
    {
        me->_matchingDone = FALSE;
        me->_interface = NULL;
        me->stopRun();
    }
}

#pragma mark -
#pragma mark Loop Functions
#pragma mark -

bool USBJack::stopRun()
{
    // No loop running
    if (_runLoop == NULL)
        return false;

    // Disable keeping
    _stayUp = false;
    
    // If we have to notify, do that
    if (_notifyPort) 
    {
        IONotificationPortDestroy(_notifyPort);
        _notifyPort = NULL;
    }
    
    // Stop loop
    if (_runLoop)
        CFRunLoopStop(_runLoop);
    _runLoop = NULL;
    
    return true;
}
void USBJack::_runCFRunLoop(USBJack* me) {
    me->_runLoop = CFRunLoopGetCurrent();
    
    // Check if we need to keep loop running
    while(me->_stayUp) {
        CFRunLoopRun();
    };
    
    // Stop
    if (me->_runLoop) {
        if (me->_runLoopSource)
            CFRunLoopRemoveSource(me->_runLoop, me->_runLoopSource, kCFRunLoopDefaultMode);
        CFRunLoopStop(me->_runLoop);
        me->_runLoop = NULL;
    }
} 
bool USBJack::run() {
    pthread_t pt;
    
    _stayUp = true;
    
    if (_runLoop==NULL) {
        pthread_create(&pt, NULL, (void*(*)(void*))_runCFRunLoop, this);
    }
    
    return true;
}

