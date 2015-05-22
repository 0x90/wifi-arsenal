/*
        
        File:			PrefsScanning.m
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


#import "PrefsScanning.h"
#import "PrefsController.h"
#import "WaveHelper.h"

@implementation PrefsScanning


-(void)updateUI {
    [_dontAskToSave setState:[[controller objectForKey:@"dontAskToSave"] boolValue]];    
    [_terminateIfClosed setState:[[controller objectForKey:@"terminateIfClosed"] boolValue]];    
}

-(IBAction)setValueForSender:(id)sender {
    if(sender == _dontAskToSave) {
        [controller setObject:[NSNumber numberWithBool:[_dontAskToSave state]] forKey:@"dontAskToSave"];    
    } else if(sender == _terminateIfClosed) {
        [controller setObject:[NSNumber numberWithBool:[_terminateIfClosed state]] forKey:@"terminateIfClosed"];    
    } else {
        DBNSLog(@"Error: Invalid sender(%@) in setValueForSender:",sender);
    }
}


@end
