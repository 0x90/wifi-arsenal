/*
        
        File:			ImportController.m
        Program:		KisMAC
	Author:			Michael Ro§berg
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

#import "ImportController.h"

@implementation ImportController

-(void)awakeFromNib
{
    _canceled = NO;
    _isFullyInititialized = NO;
    [[self window] setDelegate:self];
    [aProgressBar startAnimation:self];
}

-(void)setMax:(float)max 
{
    [aProgressBar setIndeterminate:NO];
    [aProgressBar setMinValue:0.0];
    [aProgressBar setMaxValue:(double)max];
    [aProgressBar setDoubleValue:0.0];
    [aProgressBar displayIfNeeded];
}
-(void)increment 
{
    [aProgressBar incrementBy:1.0];
    [aProgressBar displayIfNeeded];
}

-(void)stopAnimation
{
    [aProgressBar stopAnimation: self];
}

- (bool)canceled {
    return _canceled;
}

- (void)setTitle:(NSString*)title {
    [[self window] setTitle:title];
    [_title setStringValue:title];
}

- (void)setStatusField:(NSString*)status {
    [_statusField setStringValue:status];
}

- (IBAction)cancelAction:(id)sender {
    _canceled = YES;
    [aCancel setEnabled:NO];
}

- (void)terminateWithCode:(int)code {
    [[[self window] sheetParent] endSheet:[self window] returnCode:code];
}

- (void)windowDidBecomeKey:(NSNotification *)aNotification {
    _isFullyInititialized = YES;
}

- (void)closeWindow:(NSWindow *)sheet returnCode:(int)returnCode contextInfo:(void *)contextInfo 
{
    [aProgressBar stopAnimation: self];
    [NSThread sleepUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.3]];
}

@end
