/*
        
        File:			CrashReporter.h
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

#import <Cocoa/Cocoa.h>

@interface CrashReportController : NSWindowController <NSWindowDelegate>
{
    IBOutlet NSButton *_allow;
    IBOutlet NSButton *_deny;
    IBOutlet NSButton *_alwaysDeny;
    IBOutlet NSTextView *_report;
    IBOutlet NSTextView *_comment;
    IBOutlet NSTextField *_mail;
    
    CFReadStreamRef _stream;
}

- (IBAction)allowAction:(id)sender;
- (IBAction)denyAction:(id)sender;
- (IBAction)alwaysDenyAction:(id)sender;
- (void)setReport:(NSData*)data;

- (void)handleNetworkEvent:(CFStreamEventType)type;

- (void)handleBytesAvailable;
- (void)handleStreamComplete;
- (void)handleStreamError;

@end
