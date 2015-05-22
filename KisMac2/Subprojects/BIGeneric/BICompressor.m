/*
        
        File:			BICompressor.m
        Program:		BIGeneric
		Author:			Michael Rossberg
						mick@binaervarianz.de
		Description:	BIGeneric is a general purpose library.
                
        This file is part of BIGeneric.

    BIGeneric is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    BIGeneric is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with BIGeneric; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/
#import "BICompressor.h"
#import "BINSExtensions.h"

@implementation BICompressor

- (id)initWithFile:(NSString*)file 
{
	UInt32 magic = 'BIGe';
    
    magic = CFSwapInt32HostToBig(magic);
	
	self = [super init];
	if (!self) return nil;
	
	_file = gzopen([[file standardPath] UTF8String], "wb");
	if (!_file) 
    {
		return nil;
	}

	if (gzwrite(_file, &magic, sizeof(magic)) != sizeof(magic)) 
    {
		return nil;
	}

	return self;
}

- (bool)addString:(NSString*)dataset 
{
	UInt32 size = [dataset length];
    
    UInt32 sizeToWrite = CFSwapInt32HostToBig(size);
	
	if (gzwrite(_file, &sizeToWrite, sizeof(sizeToWrite)) != sizeof(sizeToWrite)) return NO;
	if (gzwrite(_file, (void*)[dataset UTF8String], size) != size) return NO;
	
	return YES;
}

- (bool)addData:(NSData*)dataset 
{
	UInt32 size = [dataset length];
	
    UInt32 sizeToWrite = CFSwapInt32HostToBig(size);
        
	if (gzwrite(_file, &sizeToWrite, sizeof(sizeToWrite)) != sizeof(sizeToWrite)) return NO;
	if (gzwrite(_file, (void*)[dataset bytes], size) != size) return NO;
	
	return YES;
}

- (void)close
{
    gzclose(_file);
}

@end
