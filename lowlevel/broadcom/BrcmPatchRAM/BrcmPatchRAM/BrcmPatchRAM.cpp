/*
 *  Released under "The GNU General Public License (GPL-2.0)"
 *
 *  This program is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License as published by the
 *  Free Software Foundation; either version 2 of the License, or (at your
 *  option) any later version.
 *
 *  This program is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 *  or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 *  for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 */

#include <IOKit/IOLib.h>
#include <IOKit/IOMessage.h>

#include <IOKit/usb/IOUSBInterface.h>
#include <IOKit/IOCatalogue.h>

#include <kern/clock.h>
#include <libkern/version.h>
#include <libkern/zlib.h>

#include "Common.h"
#include "hci.h"
#include "BrcmPatchRAM.h"

enum { kMyOffPowerState = 0, kMyOnPowerState = 1 };

static IOPMPowerState myTwoStates[2] =
{
    { kIOPMPowerStateVersion1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { kIOPMPowerStateVersion1, kIOPMPowerOn, kIOPMPowerOn, kIOPMPowerOn, 0, 0, 0, 0, 0, 0, 0, 0 }
};

OSDefineMetaClassAndStructors(BrcmPatchRAM, IOService)

OSString* BrcmPatchRAM::brcmBundleIdentifier = NULL;
OSString* BrcmPatchRAM::brcmIOClass = NULL;

bool BrcmPatchRAM::initBrcmStrings()
{
    if (!brcmBundleIdentifier)
    {
        const char* bundle = NULL;
        const char* ioclass = NULL;
        
        // OS X - Snow Leopard
        // OS X - Lion
        if (version_major == 10 || version_major == 11)
        {
            bundle = "com.apple.driver.BroadcomUSBBluetoothHCIController";
            ioclass = "BroadcomUSBBluetoothHCIController";
        }
        // OS X - Mountain Lion (12.0 until 12.4)
        else if (version_major == 12 && version_minor <= 4)
        {
            bundle = "com.apple.iokit.BroadcomBluetoothHCIControllerUSBTransport";
            ioclass = "BroadcomBluetoothHCIControllerUSBTransport";
        }
        // OS X - Mountain Lion (12.5.0)
        // OS X - Mavericks
        // OS X - Yosemite
        else if (version_major == 12 || version_major == 13 || version_major == 14)
        {
            bundle = "com.apple.iokit.BroadcomBluetoothHostControllerUSBTransport";
            ioclass = "BroadcomBluetoothHostControllerUSBTransport";
        }
        // OS X - Future releases....
        else if (version_major > 14)
        {
            AlwaysLog("Unknown new Darwin version %d.%d, using possible compatible personality.\n", version_major, version_minor);
            bundle = "com.apple.iokit.BroadcomBluetoothHostControllerUSBTransport";
            ioclass = "BroadcomBluetoothHostControllerUSBTransport";
        }
        else
        {
            AlwaysLog("Unknown Darwin version %d.%d, no compatible personality known.\n", version_major, version_minor);
        }
        brcmBundleIdentifier = OSString::withCStringNoCopy(bundle);
        brcmIOClass = OSString::withCStringNoCopy(ioclass);
    }
}

IOService* BrcmPatchRAM::probe(IOService *provider, SInt32 *probeScore)
{
    extern kmod_info_t kmod_info;
    uint64_t start_time, end_time, nano_secs;
    
    DebugLog("probe\n");
    
    AlwaysLog("Version %s starting on OS X Darwin %d.%d.\n", kmod_info.version, version_major, version_minor);

    clock_get_uptime(&start_time);

    mCompletionLock = IOLockAlloc();
    if (!mCompletionLock)
        return NULL;

    mDevice = OSDynamicCast(IOUSBDevice, provider);
    if (!mDevice)
    {
        AlwaysLog("Provider is not a USB device.\n");
        return NULL;
    }
    mDevice->retain();
    
    initBrcmStrings();
    OSString* displayName = OSDynamicCast(OSString, getProperty(kDisplayName));
    if (displayName)
        provider->setProperty(kUSBProductString, displayName);
    
    mVendorId = mDevice->GetVendorID();
    mProductId = mDevice->GetProductID();
    
    uploadFirmware();
    publishPersonality();

    clock_get_uptime(&end_time);
    absolutetime_to_nanoseconds(end_time - start_time, &nano_secs);
    uint64_t milli_secs = nano_secs / 1000000;
    AlwaysLog("Processing time %llu.%llu seconds.\n", milli_secs / 1000, milli_secs % 1000);
    
    return this;
}

bool BrcmPatchRAM::start(IOService *provider)
{
    DebugLog("start\n");

    if (!super::start(provider))
        return false;
    
    PMinit();
    registerPowerDriver(this, myTwoStates, 2);
    provider->joinPMtree(this);
    
    return true;
}

void BrcmPatchRAM::stop(IOService* provider)
{
    DebugLog("stop\n");

    OSSafeReleaseNULL(mFirmwareStore);

    PMstop();

    if (mCompletionLock)
    {
        IOLockFree(mCompletionLock);
        mCompletionLock = NULL;
    }

    OSSafeReleaseNULL(mDevice);

    super::stop(provider);
}

void BrcmPatchRAM::uploadFirmware()
{
    // get firmware here to pre-cache for eventual use on wakeup or now
    BrcmFirmwareStore* firmwareStore = getFirmwareStore();
    OSArray* instructions = NULL;
    if (!firmwareStore || !firmwareStore->getFirmware(OSDynamicCast(OSString, getProperty(kFirmwareKey))))
        return;

    if (mDevice->open(this))
    {
        // Print out additional device information
        printDeviceInfo();
        
        // Set device configuration to composite configuration index 0
        // Obtain first interface
        if (setConfiguration(0) && (mInterface = findInterface()) && mInterface->open(this))
        {
            mInterruptPipe = findPipe(kUSBInterrupt, kUSBIn);
            mBulkPipe = findPipe(kUSBBulk, kUSBOut);
            if (mInterruptPipe && mBulkPipe)
            {
                if (performUpgrade())
                    AlwaysLog("[%04x:%04x]: Firmware upgrade completed successfully.\n", mVendorId, mProductId);
                else
                    AlwaysLog("[%04x:%04x]: Firmware upgrade failed.\n", mVendorId, mProductId);
                OSSafeReleaseNULL(mReadBuffer); // mReadBuffer is allocated by performUpgrade but not released
            }
            mInterface->close(this);
        }
        
        // cleanup
        if (mInterruptPipe)
        {
            mInterruptPipe->Abort();
            mInterruptPipe->release(); // retained in findPipe
            mInterruptPipe = NULL;
        }
        if (mBulkPipe)
        {
            mBulkPipe->Abort();
            mBulkPipe->release(); // retained in findPipe
            mBulkPipe = NULL;
        }
        OSSafeReleaseNULL(mInterface);// retained in findInterface
        mDevice->close(this);
    }
}

IOReturn BrcmPatchRAM::setPowerState(unsigned long which, IOService *whom)
{
    DebugLog("setPowerState: which = 0x%lx\n", which);
    
    if (which == kMyOffPowerState)
    {
        // in the case the instance is shutting down, don't do anything
        if (mFirmwareStore)
        {
            // unload native bluetooth driver
            IOReturn result = gIOCatalogue->terminateDriversForModule(brcmBundleIdentifier, false);
            if (result != kIOReturnSuccess)
                AlwaysLog("[%04x:%04x]: failure terminating native Broadcom bluetooth (%08x)", mVendorId, mProductId, result);
            else
                DebugLog("[%04x:%04x]: success terminating native Broadcom bluetooth\n", mVendorId, mProductId);

            // unpublish native bluetooth personality
            removePersonality();
        }
    }

    return IOPMAckImplied;
}

static void setStringInDict(OSDictionary* dict, const char* key, const char* value)
{
    OSString* str = OSString::withCStringNoCopy(value);
    if (str)
    {
        dict->setObject(key, str);
        str->release();
    }
}

static void setNumberInDict(OSDictionary* dict, const char* key, UInt16 value)
{
    OSNumber* num = OSNumber::withNumber(value, 16);
    if (num)
    {
        dict->setObject(key, num);
        num->release();
    }
}

#ifdef DEBUG
void BrcmPatchRAM::printPersonalities()
{
    // Matching dictionary for the current device
    OSDictionary* dict = OSDictionary::withCapacity(5);
    if (!dict) return;
    setStringInDict(dict, kIOProviderClassKey, kIOUSBDeviceClassName);
    setNumberInDict(dict, kUSBProductID, mProductId);
    setNumberInDict(dict, kUSBVendorID, mVendorId);
    
    SInt32 generatonCount;
    if (OSOrderedSet* set = gIOCatalogue->findDrivers(dict, &generatonCount))
    {
        AlwaysLog("[%04x:%04x]: %d matching driver personalities.\n", mVendorId, mProductId, set->getCount());
        if (OSCollectionIterator* iterator = OSCollectionIterator::withCollection(set))
        {
            while (OSDictionary* personality = static_cast<OSDictionary*>(iterator->getNextObject()))
            {
                OSString* bundleId = OSDynamicCast(OSString, personality->getObject(kBundleIdentifier));
                AlwaysLog("[%04x:%04x]: existing IOKit personality \"%s\".\n", mVendorId, mProductId, bundleId->getCStringNoCopy());
            }
            iterator->release();
        }
        set->release();
    }
    dict->release();
}
#endif //DEBUG

void BrcmPatchRAM::removePersonality()
{
    DebugLog("removePersonality\n");
    
#ifdef DEBUG
    printPersonalities();
#endif
    
    // remove Broadcom matching personality
    OSDictionary* dict = OSDictionary::withCapacity(5);
    if (!dict) return;
    setStringInDict(dict, kIOProviderClassKey, kIOUSBDeviceClassName);
    setNumberInDict(dict, kUSBProductID, mProductId);
    setNumberInDict(dict, kUSBVendorID, mVendorId);
    dict->setObject(kBundleIdentifier, brcmBundleIdentifier);
    gIOCatalogue->removeDrivers(dict, true);

    // remove generic matching personality
    dict->removeObject(kUSBProductID);
    dict->removeObject(kUSBVendorID);
    setStringInDict(dict, kBundleIdentifier, "com.apple.iokit.IOBluetoothHostControllerUSBTransport");
    setNumberInDict(dict, "bDeviceClass", 224);
    setNumberInDict(dict, "bDeviceProtocol", 1);
    setNumberInDict(dict, "bDeviceSubClass", 1);
    gIOCatalogue->removeDrivers(dict, true);
    dict->release();
    
#ifdef DEBUG
    printPersonalities();
#endif
}

void BrcmPatchRAM::publishPersonality()
{
    // Matching dictionary for the current device
    OSDictionary* dict = OSDictionary::withCapacity(5);
    if (!dict) return;
    setStringInDict(dict, kIOProviderClassKey, kIOUSBDeviceClassName);
    setNumberInDict(dict, kUSBProductID, mProductId);
    setNumberInDict(dict, kUSBVendorID, mVendorId);
    
    // Retrieve currently matching IOKit driver personalities
    OSDictionary* personality = NULL;
    SInt32 generationCount;
    if (OSOrderedSet* set = gIOCatalogue->findDrivers(dict, &generationCount))
    {
        if (set->getCount())
            DebugLog("[%04x:%04x]: %d matching driver personalities.\n", mVendorId, mProductId, set->getCount());
        
        if (OSCollectionIterator* iterator = OSCollectionIterator::withCollection(set))
        {
            while ((personality = OSDynamicCast(OSDictionary, iterator->getNextObject())))
            {
                if (OSString* bundleId = OSDynamicCast(OSString, personality->getObject(kBundleIdentifier)))
                    if (strncmp(bundleId->getCStringNoCopy(), kAppleBundlePrefix, strlen(kAppleBundlePrefix)) == 0)
                    {
                        AlwaysLog("[%04x:%04x]: Found existing IOKit personality \"%s\".\n", mVendorId, mProductId, bundleId->getCStringNoCopy());
                        break;
                    }
            }
            iterator->release();
        }
        set->release();
    }
    
    if (!personality && brcmBundleIdentifier)
    {
        // OS X does not have a driver personality for this device yet, publish one
        DebugLog("brcmBundIdentifier: \"%s\"\n", brcmBundleIdentifier->getCStringNoCopy());
        DebugLog("brcmIOClass: \"%s\"\n", brcmIOClass->getCStringNoCopy());
        dict->setObject(kBundleIdentifier, brcmBundleIdentifier);
        dict->setObject(kIOClassKey, brcmIOClass);
        
        // Add new personality into the kernel
        if (OSArray* array = OSArray::withCapacity(1))
        {
            array->setObject(dict);
            if (gIOCatalogue->addDrivers(array, true))
                AlwaysLog("[%04x:%04x]: Published new IOKit personality.\n", mVendorId, mProductId);
            else
                AlwaysLog("[%04x:%04x]: ERROR in addDrivers for new IOKit personality.\n", mVendorId, mProductId);
            array->release();
        }
    }
    dict->release();

#ifdef DEBUG
    printPersonalities();
#endif
}

BrcmFirmwareStore* BrcmPatchRAM::getFirmwareStore()
{
    if (!mFirmwareStore)
        mFirmwareStore = OSDynamicCast(BrcmFirmwareStore, waitForMatchingService(serviceMatching(kBrcmFirmwareStoreService), 2000UL*1000UL*1000UL));
    
    if (!mFirmwareStore)
        AlwaysLog("[%04x:%04x]: BrcmFirmwareStore does not appear to be available.\n", mVendorId, mProductId);
    
    return mFirmwareStore;
}

void BrcmPatchRAM::printDeviceInfo()
{
    char product[255];
    char manufacturer[255];
    char serial[255];
    
    // Retrieve device information
    mDevice->GetStringDescriptor(mDevice->GetProductStringIndex(), product, sizeof(product));
    mDevice->GetStringDescriptor(mDevice->GetManufacturerStringIndex(), manufacturer, sizeof(manufacturer));
    mDevice->GetStringDescriptor(mDevice->GetSerialNumberStringIndex(), serial, sizeof(serial));
    
    AlwaysLog("[%04x:%04x]: USB [%s v%d] \"%s\" by \"%s\"\n",
              mVendorId,
              mProductId,
              serial,
              mDevice->GetDeviceRelease(),
              product,
              manufacturer);
}

int BrcmPatchRAM::getDeviceStatus()
{
    IOReturn result;
    USBStatus status;
    
    if ((result = mDevice->GetDeviceStatus(&status)) != kIOReturnSuccess)
    {
        AlwaysLog("[%04x:%04x]: Unable to get device status (\"%s\" 0x%08x).\n", mVendorId, mProductId, stringFromReturn(result), result);
        return 0;
    }
    else
        DebugLog("[%04x:%04x]: Device status 0x%08x.\n", mVendorId, mProductId, (int)status);
    
    return (int)status;
}

bool BrcmPatchRAM::resetDevice()
{
    IOReturn result;
    
    if ((result = mDevice->ResetDevice()) != kIOReturnSuccess)
    {
        AlwaysLog("[%04x:%04x]: Failed to reset the device (\"%s\" 0x%08x).\n", mVendorId, mProductId, stringFromReturn(result), result);
        return false;
    }
    else
        DebugLog("[%04x:%04x]: Device reset.\n", mVendorId, mProductId);
    
    return true;
}

bool BrcmPatchRAM::setConfiguration(int configurationIndex)
{
    IOReturn result;
    const IOUSBConfigurationDescriptor* configurationDescriptor;
    UInt8 currentConfiguration = 0xFF;
    
    // Find the first config/interface
    UInt8 numconf = 0;
    
    if ((numconf = mDevice->GetNumConfigurations()) < (configurationIndex + 1))
    {
        AlwaysLog("[%04x:%04x]: Composite configuration index %d is not available, %d total composite configurations.\n",
                  mVendorId, mProductId, configurationIndex, numconf);
        return false;
    }
    else
        DebugLog("[%04x:%04x]: Available composite configurations: %d.\n", mVendorId, mProductId, numconf);
    
    configurationDescriptor = mDevice->GetFullConfigurationDescriptor(configurationIndex);
    
    // Set the configuration to the requested configuration index
    if (!configurationDescriptor)
    {
        AlwaysLog("[%04x:%04x]: No configuration descriptor for configuration index: %d.\n", mVendorId, mProductId, configurationIndex);
        return false;
    }
    
    if ((result = mDevice->GetConfiguration(&currentConfiguration)) != kIOReturnSuccess)
    {
        AlwaysLog("[%04x:%04x]: Unable to retrieve active configuration (\"%s\" 0x%08x).\n", mVendorId, mProductId, stringFromReturn(result), result);
        return false;
    }
    
    // Device is already configured
    if (currentConfiguration != 0)
    {
        DebugLog("[%04x:%04x]: Device configuration is already set to configuration index %d.\n",
                 mVendorId, mProductId, configurationIndex);
        return true;
    }
    
    // Set the configuration to the first configuration
    if ((result = mDevice->SetConfiguration(this, configurationDescriptor->bConfigurationValue, true)) != kIOReturnSuccess)
    {
        AlwaysLog("[%04x:%04x]: Unable to (re-)configure device (\"%s\" 0x%08x).\n", mVendorId, mProductId, stringFromReturn(result), result);
        return false;
    }
    
    DebugLog("[%04x:%04x]: Set device configuration to configuration index %d successfully.\n",
             mVendorId, mProductId, configurationIndex);
    
    return true;
}

IOUSBInterface* BrcmPatchRAM::findInterface()
{
    // Find the interface for bulk endpoint transfers
    IOUSBFindInterfaceRequest request;
    request.bAlternateSetting  = kIOUSBFindInterfaceDontCare;
    request.bInterfaceClass    = kIOUSBFindInterfaceDontCare;
    request.bInterfaceSubClass = kIOUSBFindInterfaceDontCare;
    request.bInterfaceProtocol = kIOUSBFindInterfaceDontCare;
    
    if (IOUSBInterface* interface = mDevice->FindNextInterface(NULL, &request))
    {
        interface->retain();
        DebugLog("[%04x:%04x]: Interface %d (class %02x, subclass %02x, protocol %02x) located.\n",
                 mVendorId,
                 mProductId,
                 interface->GetInterfaceNumber(),
                 interface->GetInterfaceClass(),
                 interface->GetInterfaceSubClass(),
                 interface->GetInterfaceProtocol());
        
        return interface;
    }
    
    AlwaysLog("[%04x:%04x]: No interface could be located.\n", mVendorId, mProductId);
    
    return NULL;
}

IOUSBPipe* BrcmPatchRAM::findPipe(UInt8 type, UInt8 direction)
{
    IOUSBFindEndpointRequest findEndpointRequest;
    findEndpointRequest.type = type;
    findEndpointRequest.direction = direction;
    
    if (IOUSBPipe* pipe = mInterface->FindNextPipe(NULL, &findEndpointRequest))
    {
        pipe->retain();
#ifdef DEBUG
        const IOUSBEndpointDescriptor* desc = pipe->GetEndpointDescriptor();
        if (!desc)
            DebugLog("[%04x:%04x]: No endpoint descriptor for pipe.\n", mVendorId, mProductId);
        else
            DebugLog("[%04x:%04x]: Located pipe at 0x%02x.\n", mVendorId, mProductId, desc->bEndpointAddress);
#endif
        return pipe;
    }
    else
        AlwaysLog("[%04x:%04x]: Unable to locate pipe.\n", mVendorId, mProductId);
    
    return NULL;
}

bool BrcmPatchRAM::continuousRead()
{
    if (!mReadBuffer)
    {
        mReadBuffer = IOBufferMemoryDescriptor::inTaskWithOptions(kernel_task, 0, 0x200);
        if (!mReadBuffer)
        {
            AlwaysLog("[%04x:%04x]: continuousRead - failed to allocate read buffer.\n", mVendorId, mProductId);
            return false;
        }
        mInterruptCompletion.target = this;
        mInterruptCompletion.action = readCompletion;
        mInterruptCompletion.parameter = NULL;
    }

    IOReturn result = mReadBuffer->prepare();
    if (result != kIOReturnSuccess)
    {
        AlwaysLog("[%04x:%04x]: continuousRead - failed to prepare buffer (0x%08x)\n", mVendorId, mProductId, result);
        return false;
    }

    if ((result = mInterruptPipe->Read(mReadBuffer, 0, 0, mReadBuffer->getLength(), &mInterruptCompletion)) != kIOReturnSuccess)
    {
        AlwaysLog("[%04x:%04x]: continuousRead - Failed to queue read (0x%08x)\n", mVendorId, mProductId, result);

        if (result == kIOUSBPipeStalled)
        {
            mInterruptPipe->Reset();
            result = mInterruptPipe->Read(mReadBuffer, 0, 0, mReadBuffer->getLength(), &mInterruptCompletion);
            
            if (result != kIOReturnSuccess)
            {
                AlwaysLog("[%04x:%04x]: continuousRead - Failed, read dead (0x%08x)\n", mVendorId, mProductId, result);
                return false;
            }
        }
    }

    return true;
}

void BrcmPatchRAM::readCompletion(void* target, void* parameter, IOReturn status, UInt32 bufferSizeRemaining)
{
    BrcmPatchRAM *me = (BrcmPatchRAM*)target;

    IOLockLock(me->mCompletionLock);

    IOReturn result = me->mReadBuffer->complete();
    if (result != kIOReturnSuccess)
        DebugLog("[%04x:%04x]: ReadCompletion failed to complete read buffer (\"%s\" 0x%08x).\n", me->mVendorId, me->mProductId, me->stringFromReturn(result), result);

    switch (status)
    {
        case kIOReturnSuccess:
            me->hciParseResponse(me->mReadBuffer->getBytesNoCopy(), me->mReadBuffer->getLength() - bufferSizeRemaining, NULL, NULL);
            break;
        case kIOReturnAborted:
            AlwaysLog("[%04x:%04x]: readCompletion - Return aborted (0x%08x)\n", me->mVendorId, me->mProductId, status);
            me->mDeviceState = kUpdateAborted;
            break;
        case kIOReturnNoDevice:
            AlwaysLog("[%04x:%04x]: readCompletion - No such device (0x%08x)\n", me->mVendorId, me->mProductId, status);
            me->mDeviceState = kUpdateAborted;
            break;
        case kIOUSBTransactionTimeout:
            AlwaysLog("[%04x:%04x]: readCompletion - Transaction timeout (0x%08x)\n", me->mVendorId, me->mProductId, status);
            break;
        case kIOReturnNotResponding:
            AlwaysLog("[%04x:%04x]: Not responding - Delaying next read.\n", me->mVendorId, me->mProductId);
            me->mInterruptPipe->ClearStall();
            break;
        default:
            AlwaysLog("[%04x:%04x]: readCompletion - Unknown error (0x%08x)\n", me->mVendorId, me->mProductId, status);
            me->mDeviceState = kUpdateAborted;
            break;
    }

    IOLockUnlock(me->mCompletionLock);

    // wake waiting task in performUpgrade (in IOLockSleep)...
    IOLockWakeup(me->mCompletionLock, NULL, true);
}

IOReturn BrcmPatchRAM::hciCommand(void * command, UInt16 length)
{
    IOReturn result;
    
    IOUSBDevRequest request =
    {
        .bmRequestType = USBmakebmRequestType(kUSBOut, kUSBClass, kUSBDevice),
        .bRequest = 0,
        .wValue = 0,
        .wIndex = 0,
        .wLength = length,
        .pData = command
    };
    
    if ((result = mInterface->DeviceRequest(&request)) != kIOReturnSuccess)
        AlwaysLog("[%04x:%04x]: device request failed (\"%s\" 0x%08x).\n", mVendorId, mProductId, stringFromReturn(result), result);
    
    return result;
}

IOReturn BrcmPatchRAM::hciParseResponse(void* response, UInt16 length, void* output, UInt8* outputLength)
{
    HCI_RESPONSE* header = (HCI_RESPONSE*)response;
    IOReturn result = kIOReturnSuccess;

    switch (header->eventCode)
    {
        case HCI_EVENT_COMMAND_COMPLETE:
        {
            HCI_COMMAND_COMPLETE* event = (HCI_COMMAND_COMPLETE*)response;
            
            switch (event->opcode)
            {
                case HCI_OPCODE_READ_VERBOSE_CONFIG:
                    DebugLog("[%04x:%04x]: READ VERBOSE CONFIG complete (status: 0x%02x, length: %d bytes).\n",
                             mVendorId, mProductId, event->status, header->length);
                    
                    mFirmareVersion = *(UInt16*)(((char*)response) + 10);
                    
                    DebugLog("[%04x:%04x]: Firmware version: v%d.\n",
                             mVendorId, mProductId, mFirmareVersion + 0x1000);
                    
                    // Device does not require a firmware patch at this time
                    if (mFirmareVersion > 0)
                        mDeviceState = kUpdateComplete;
                    else
                        mDeviceState = kFirmwareVersion;
                    break;
                case HCI_OPCODE_DOWNLOAD_MINIDRIVER:
                    DebugLog("[%04x:%04x]: DOWNLOAD MINIDRIVER complete (status: 0x%02x, length: %d bytes).\n",
                             mVendorId, mProductId, event->status, header->length);
                    
                    mDeviceState = kMiniDriverComplete;
                    break;
                case HCI_OPCODE_LAUNCH_RAM:
                    //DebugLog("[%04x:%04x]: LAUNCH RAM complete (status: 0x%02x, length: %d bytes).\n",
                    //          mVendorId, mProductId, event->status, header->length);
                    
                    mDeviceState = kInstructionWritten;
                    break;
                case HCI_OPCODE_END_OF_RECORD:
                    DebugLog("[%04x:%04x]: END OF RECORD complete (status: 0x%02x, length: %d bytes).\n",
                             mVendorId, mProductId, event->status, header->length);
                    
                    mDeviceState = kFirmwareWritten;
                    break;
                case HCI_OPCODE_RESET:
                    DebugLog("[%04x:%04x]: RESET complete (status: 0x%02x, length: %d bytes).\n",
                             mVendorId, mProductId, event->status, header->length);
                    
                    mDeviceState = kResetComplete;
                    break;
                default:
                    DebugLog("[%04x:%04x]: Event COMMAND COMPLETE (opcode 0x%04x, status: 0x%02x, length: %d bytes).\n",
                             mVendorId, mProductId, event->opcode, event->status, header->length);
                    break;
            }
            
            if (output && outputLength)
            {
                bzero(output, *outputLength);
                
                // Return the received data
                if (*outputLength >= length)
                {
                    DebugLog("[%04x:%04x]: Returning output data %d bytes.\n", mVendorId, mProductId, length);
                    
                    *outputLength = length;
                    memcpy(output, response, length);
                }
                else
                    // Not enough buffer space for data
                    result = kIOReturnMessageTooLarge;
            }
            break;
        }
        case HCI_EVENT_NUM_COMPLETED_PACKETS:
            DebugLog("[%04x:%04x]: Number of completed packets.\n", mVendorId, mProductId);
            break;
        case HCI_EVENT_CONN_COMPLETE:
            DebugLog("[%04x:%04x]: Connection complete event.\n", mVendorId, mProductId);
            break;
        case HCI_EVENT_DISCONN_COMPLETE:
            DebugLog("[%04x:%04x]: Disconnection complete. event\n", mVendorId, mProductId);
            break;
        case HCI_EVENT_HARDWARE_ERROR:
            DebugLog("[%04x:%04x]: Hardware error\n", mVendorId, mProductId);
            break;
        case HCI_EVENT_MODE_CHANGE:
            DebugLog("[%04x:%04x]: Mode change event.\n", mVendorId, mProductId);
            break;
        case HCI_EVENT_LE_META:
            DebugLog("[%04x:%04x]: Low-Energy meta event.\n", mVendorId, mProductId);
            break;
        default:
            DebugLog("[%04x:%04x]: Unknown event code (0x%02x).\n", mVendorId, mProductId, header->eventCode);
            break;
    }
    
    return result;
}

IOReturn BrcmPatchRAM::bulkWrite(const void* data, UInt16 length)
{
    IOReturn result;
    
    if (IOMemoryDescriptor* buffer = IOMemoryDescriptor::withAddress((void*)data, length, kIODirectionIn))
    {
        if ((result = buffer->prepare()) == kIOReturnSuccess)
        {
            if ((result = mBulkPipe->Write(buffer, 0, 0, buffer->getLength(), (IOUSBCompletion*)NULL)) == kIOReturnSuccess)
            {
                //DEBUG_LOG("%s: Wrote %d bytes to bulk pipe.\n", getName(), length);
            }
            else
                AlwaysLog("[%04x:%04x]: Failed to write to bulk pipe (\"%s\" 0x%08x).\n", mVendorId, mProductId, stringFromReturn(result), result);
        }
        else
            AlwaysLog("[%04x:%04x]: Failed to prepare bulk write memory buffer (\"%s\" 0x%08x).\n", mVendorId, mProductId, stringFromReturn(result), result);
        
        if ((result = buffer->complete()) != kIOReturnSuccess)
            AlwaysLog("[%04x:%04x]: Failed to complete bulk write memory buffer (\"%s\" 0x%08x).\n", mVendorId, mProductId, stringFromReturn(result), result);
        
        buffer->release();
    }
    else
    {
        AlwaysLog("[%04x:%04x]: Unable to allocate bulk write buffer.\n", mVendorId, mProductId);
        result = kIOReturnNoMemory;
    }
    
    return result;
}

bool BrcmPatchRAM::performUpgrade()
{
    BrcmFirmwareStore* firmwareStore;
    OSArray* instructions = NULL;
    OSCollectionIterator* iterator = NULL;
    OSData* data;
#ifdef DEBUG
    DeviceState previousState = kUnknown;
#endif

    IOLockLock(mCompletionLock);
    mDeviceState = kInitialize;

    while (true)
    {
#ifdef DEBUG
        if (mDeviceState != kInstructionWrite && mDeviceState != kInstructionWritten)
            DebugLog("[%04x:%04x]: State \"%s\" --> \"%s\".\n", mVendorId, mProductId, getState(previousState), getState(mDeviceState));
        previousState = mDeviceState;
#endif

        // Break out when done
        if (mDeviceState == kUpdateAborted || mDeviceState == kUpdateComplete)
            break;

        // Note on following switch/case:
        //   use 'break' when a response from io completion callback is expected
        //   use 'continue' when a change of state with no expected response (loop again)

        switch (mDeviceState)
        {
            case kInitialize:
                hciCommand(&HCI_VSC_READ_VERBOSE_CONFIG, sizeof(HCI_VSC_READ_VERBOSE_CONFIG));
                break;

            case kFirmwareVersion:
                // Unable to retrieve firmware store
                if (!(firmwareStore = getFirmwareStore()))
                {
                    mDeviceState = kUpdateAborted;
                    continue;
                }
                instructions = firmwareStore->getFirmware(OSDynamicCast(OSString, getProperty(kFirmwareKey)));
                // Unable to retrieve firmware instructions
                if (!instructions)
                {
                    mDeviceState = kUpdateAborted;
                    continue;
                }

                // Initiate firmware upgrade
                hciCommand(&HCI_VSC_DOWNLOAD_MINIDRIVER, sizeof(HCI_VSC_DOWNLOAD_MINIDRIVER));
                break;

            case kMiniDriverComplete:
                // Write firmware data to bulk pipe
                iterator = OSCollectionIterator::withCollection(instructions);
                if (!iterator)
                {
                    mDeviceState = kUpdateAborted;
                    continue;
                }

                // If this IOSleep is not issued, the device is not ready to receive
                // the firmware instructions and we will deadlock due to lack of
                // responses.
                IOSleep(10);

                // Write first 2 instructions to trigger response
                if ((data = OSDynamicCast(OSData, iterator->getNextObject())))
                    bulkWrite(data->getBytesNoCopy(), data->getLength());
                if ((data = OSDynamicCast(OSData, iterator->getNextObject())))
                    bulkWrite(data->getBytesNoCopy(), data->getLength());
                break;

            case kInstructionWrite:
                // should never happen, but would cause a crash
                if (!iterator)
                {
                    mDeviceState = kUpdateAborted;
                    continue;
                }

                if ((data = OSDynamicCast(OSData, iterator->getNextObject())))
                    bulkWrite(data->getBytesNoCopy(), data->getLength());
                else
                    // Firmware data fully written
                    hciCommand(&HCI_VSC_END_OF_RECORD, sizeof(HCI_VSC_END_OF_RECORD));
                break;

            case kInstructionWritten:
                mDeviceState = kInstructionWrite;
                continue;

            case kFirmwareWritten:
                hciCommand(&HCI_RESET, sizeof(HCI_RESET));
                break;

            case kResetComplete:
                resetDevice();
                getDeviceStatus();
                mDeviceState = kUpdateComplete;
                continue;

            case kUnknown:
            case kUpdateComplete:
            case kUpdateAborted:
                DebugLog("Error: kUnkown/kUpdateComplete/kUpdateAborted cases should be unreachable.\n");
                break;
        }

        // queue async read
        if (!continuousRead())
        {
            mDeviceState = kUpdateAborted;
            continue;
        }
        // wait for completion of the async read
        IOLockSleep(mCompletionLock, NULL, 0);
    }

    IOLockUnlock(mCompletionLock);
    OSSafeRelease(iterator);

    return mDeviceState == kUpdateComplete;
}

#ifdef DEBUG
const char* BrcmPatchRAM::getState(DeviceState deviceState)
{
    static const IONamedValue state_values[] = {
        {kUnknown,            "Unknown"              },
        {kInitialize,         "Initialize"           },
        {kFirmwareVersion,    "Firmware version"     },
        {kMiniDriverComplete, "Mini-driver complete" },
        {kInstructionWrite,   "Instruction write"    },
        {kInstructionWritten, "Instruction written"  },
        {kFirmwareWritten,    "Firmware written"     },
        {kResetComplete,      "Reset complete"       },
        {kUpdateComplete,     "Update complete"      },
        {0,                   NULL                   }
    };
    
    return IOFindNameForValue(deviceState, state_values);
}
#endif //DEBUG

#ifndef kIOUSBClearPipeStallNotRecursive
// from 10.7 SDK
#define kIOUSBClearPipeStallNotRecursive iokit_usb_err(0x48)
#endif

const char* BrcmPatchRAM::stringFromReturn(IOReturn rtn)
{
    static const IONamedValue IOReturn_values[] = {
        {kIOReturnIsoTooOld,          "Isochronous I/O request for distant past"     },
        {kIOReturnIsoTooNew,          "Isochronous I/O request for distant future"   },
        {kIOReturnNotFound,           "Data was not found"                           },
        {kIOUSBUnknownPipeErr,        "Pipe ref not recognized"                      },
        {kIOUSBTooManyPipesErr,       "Too many pipes"                               },
        {kIOUSBNoAsyncPortErr,        "No async port"                                },
        {kIOUSBNotEnoughPowerErr,     "Not enough power for selected configuration"  },
        {kIOUSBEndpointNotFound,      "Endpoint not found"                           },
        {kIOUSBConfigNotFound,        "Configuration not found"                      },
        {kIOUSBTransactionTimeout,    "Transaction timed out"                        },
        {kIOUSBTransactionReturned,   "Transaction has been returned to the caller"  },
        {kIOUSBPipeStalled,           "Pipe has stalled, error needs to be cleared"  },
        {kIOUSBInterfaceNotFound,     "Interface reference not recognized"           },
        {kIOUSBLowLatencyBufferNotPreviouslyAllocated,
            "Attempted to user land low latency isoc calls w/out calling PrepareBuffer" },
        {kIOUSBLowLatencyFrameListNotPreviouslyAllocated,
            "Attempted to user land low latency isoc calls w/out calling PrepareBuffer" },
        {kIOUSBHighSpeedSplitError,   "Error on hi-speed bus doing split transaction"},
        {kIOUSBSyncRequestOnWLThread, "Synchronous USB request on workloop thread."  },
        {kIOUSBDeviceNotHighSpeed,    "The device is not a high speed device."       },
        {kIOUSBClearPipeStallNotRecursive,
            "IOUSBPipe::ClearPipeStall should not be called rescursively"               },
        {kIOUSBLinkErr,               "USB link error"                               },
        {kIOUSBNotSent2Err,           "Transaction not sent"                         },
        {kIOUSBNotSent1Err,           "Transaction not sent"                         },
        {kIOUSBNotEnoughPipesErr,     "Not enough pipes in interface"                },
        {kIOUSBBufferUnderrunErr,     "Buffer Underrun (Host hardware failure)"      },
        {kIOUSBBufferOverrunErr,      "Buffer Overrun (Host hardware failure"        },
        {kIOUSBReserved2Err,          "Reserved"                                     },
        {kIOUSBReserved1Err,          "Reserved"                                     },
        {kIOUSBWrongPIDErr,           "Pipe stall, Bad or wrong PID"                 },
        {kIOUSBPIDCheckErr,           "Pipe stall, PID CRC error"                    },
        {kIOUSBDataToggleErr,         "Pipe stall, Bad data toggle"                  },
        {kIOUSBBitstufErr,            "Pipe stall, bitstuffing"                      },
        {kIOUSBCRCErr,                "Pipe stall, bad CRC"                          },
        {0,                           NULL                                           }
    };
    
    const char* result = IOFindNameForValue(rtn, IOReturn_values);
    
    if (result)
        return result;
    
    return super::stringFromReturn(rtn);
}