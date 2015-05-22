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

#ifndef __BrcmPatchRAM__BrcmFirmwareStore__
#define __BrcmPatchRAM__BrcmFirmwareStore__

#include <IOKit/usb/IOUSBDevice.h>

#define kBrcmFirmwareStoreService   "BrcmFirmwareStore"

class BrcmFirmwareStore : public IOService
{
    private:
        typedef IOService super;
        OSDeclareDefaultStructors(BrcmFirmwareStore);
    
        OSDictionary* mFirmwares;
    
        OSData* decompressFirmware(OSData* firmware);
        OSArray* parseFirmware(OSData* firmwareData);
        OSArray* loadFirmware(OSString* firmwareIdentifier);
    public:
        virtual bool start(IOService *provider);
        virtual void stop(IOService *provider);
    
        OSArray* getFirmware(OSString* firmwareIdentifier);
};

#endif /* defined(__BrcmPatchRAM__BrcmFirmwareStore__) */
