/*
        
        File:			DownloadMapController.h
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
#import <AppKit/AppKit.h>

@interface DownloadMapController : NSWindowController <NSWindowDelegate>
{
    IBOutlet NSButton* _okButton;
    IBOutlet NSButton* _cancelButton;
    IBOutlet NSTextField* _width;
    IBOutlet NSTextField* _height;
    IBOutlet NSTextField* _latitude;
    IBOutlet NSTextField* _longitude;
    IBOutlet NSPopUpButton* _nsButton;
    IBOutlet NSPopUpButton* _ewButton;
    IBOutlet NSPopUpButton* _server;
    IBOutlet NSPopUpButton* _scale;
}

- (IBAction)selectOtherServer:(id)sender;
- (IBAction)okAction:(id)sender;
- (IBAction)cancelAction:(id)sender;
- (void)setCoordinates:(waypoint)wp;

@end
