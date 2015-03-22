/*
        
        File:			ScriptController.h
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


@interface ScriptController : NSObject {

}

- (IBAction)showNetworks:(id)sender;
- (IBAction)showTrafficView:(id)sender;
- (IBAction)showMap:(id)sender;
- (IBAction)showDetails:(id)sender;

- (IBAction)toggleScan:(id)sender;

- (IBAction)new:(id)sender;

- (IBAction)openKisMACFile:(id)sender;
- (IBAction)openKisMAPFile:(id)sender;

- (IBAction)importKisMACFile:(id)sender;
- (IBAction)importImageForMap:(id)sender;
- (IBAction)importPCPFile:(id)sender;

- (IBAction)saveKisMACFile:(id)sender;
- (IBAction)saveKisMACFileAs:(id)sender;
- (IBAction)saveKisMAPFile:(id)sender;

- (IBAction)bruteforceNewsham:(id)sender;
- (IBAction)bruteforce40bitLow:(id)sender;
- (IBAction)bruteforce40bitAlpha:(id)sender;
- (IBAction)bruteforce40bitAll:(id)sender;

- (IBAction)wordlist40bitApple:(id)sender;
- (IBAction)wordlist104bitApple:(id)sender;
- (IBAction)wordlist104bitMD5:(id)sender;

- (IBAction)wordlistWPA:(id)sender;
- (IBAction)wordlistLEAP:(id)sender;

- (IBAction)weakSchedulingAttack40And104bit:(id)sender;
- (IBAction)weakSchedulingAttack40bit:(id)sender;
- (IBAction)weakSchedulingAttack104bit:(id)sender;

- (IBAction)showNetworksInMap:(id)sender;
- (IBAction)showTraceInMap:(id)sender;
@end
