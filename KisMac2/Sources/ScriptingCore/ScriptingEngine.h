/*
        
        File:			ScriptingEngine.h
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

#import <Cocoa/Cocoa.h>


@interface ScriptingEngine : NSObject {

}

+ (BOOL)selfSendEvent:(AEEventID)event withClass:(AEEventClass)class andArgs:(NSDictionary*)args;
+ (BOOL)selfSendEvent:(AEEventID)event withArgs:(NSDictionary*)args;
+ (BOOL)selfSendEvent:(AEEventID)event withClass:(AEEventClass)class andDefaultArg:(NSAppleEventDescriptor*)arg;
+ (BOOL)selfSendEvent:(AEEventID)event withClass:(AEEventClass)class andDefaultArgString:(NSString*)arg;
+ (BOOL)selfSendEvent:(AEEventID)event withDefaultArgString:(NSString*)arg;
+ (BOOL)selfSendEvent:(AEEventID)event withDefaultArg:(NSAppleEventDescriptor*)arg;
+ (BOOL)selfSendEvent:(AEEventID)event;

@end
