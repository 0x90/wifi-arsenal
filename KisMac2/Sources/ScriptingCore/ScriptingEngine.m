/*
        
        File:			ScriptingEngine.m
        Program:		KisMAC
	Author:			Michael Rossberg
				mick@binaervarianz.de
	Description:		KisMAC is a wireless stumbler for MacOS X.
                
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

#import "ScriptingEngine.h"
#import <Carbon/Carbon.h>

@implementation ScriptingEngine

+ (BOOL)selfSendEvent:(AEEventID)event withClass:(AEEventClass)class andArgs:(NSDictionary*)args
{
    BOOL result = NO;
    
    AppleEvent  reply;
    ProcessSerialNumber	theCurrentProcess = { 0, kCurrentProcess };
    NSEnumerator *enu;
    NSString *ae;
    NSParameterAssert(args);
    
    NSAppleEventDescriptor *target =  [NSAppleEventDescriptor descriptorWithDescriptorType:typeProcessSerialNumber
																					 bytes:(void*)&theCurrentProcess
																					length:sizeof(theCurrentProcess)];

    NSAppleEventDescriptor *e = [NSAppleEventDescriptor appleEventWithEventClass:class
																		 eventID:event
																targetDescriptor:target
																		returnID:kAutoGenerateReturnID
																   transactionID:kAnyTransactionID];
    
    enu = [args keyEnumerator];
    while ((ae = [enu nextObject]))
    {
        [e setDescriptor:args[ae] forKeyword:[ae intValue]];
    }
    
	OSErr err = AESend([e aeDesc], &reply, kAEWaitReply, 0, kAEDefaultTimeout, NULL, NULL);
    if(noErr == err)
    {
        NSAppleEventDescriptor *replyDesc = [[NSAppleEventDescriptor alloc] initWithAEDescNoCopy:&reply];
        NSAppleEventDescriptor *resultDesc = [replyDesc paramDescriptorForKeyword: keyDirectObject];
    
        if (resultDesc)
        {
            result = [resultDesc booleanValue];
        }
    }
    
    return result;
}

+ (BOOL)selfSendEvent:(AEEventID)event withArgs:(NSDictionary*)args
{
    return [ScriptingEngine selfSendEvent:event
								withClass:'BIKM'
								  andArgs:args];
}

+ (BOOL)selfSendEvent:(AEEventID)event withClass:(AEEventClass)class andDefaultArg:(NSAppleEventDescriptor*)arg
{
    NSDictionary *args = @{};
    
    if (arg)
    {
        args = @{[NSString stringWithFormat:@"%d", keyDirectObject]: arg};
    }
    
    return [ScriptingEngine selfSendEvent:event
								withClass:class
								  andArgs:args];
}

+ (BOOL)selfSendEvent:(AEEventID)event withClass:(AEEventClass)class andDefaultArgString:(NSString*)arg
{
    return [ScriptingEngine selfSendEvent:event
								withClass:class
							andDefaultArg:[NSAppleEventDescriptor descriptorWithString:arg]];
}

+ (BOOL)selfSendEvent:(AEEventID)event withDefaultArgString:(NSString*)arg
{
    return [ScriptingEngine selfSendEvent:event
								withClass:'BIKM'
					  andDefaultArgString:arg];
}

+ (BOOL)selfSendEvent:(AEEventID)event withDefaultArg:(NSAppleEventDescriptor*)arg
{
    return [ScriptingEngine selfSendEvent:event
								withClass:'BIKM'
							andDefaultArg:arg];
}

+ (BOOL)selfSendEvent:(AEEventID)event
{
    return [ScriptingEngine selfSendEvent:event
						   withDefaultArg:nil];
}

@end
