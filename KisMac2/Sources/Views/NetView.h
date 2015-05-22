/*
        
        File:			NetView.h
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
#import "WavePacket.h"
#import "BIImageView.h"

@class WaveNet;

@interface NetView : BIImageView {
    NSString        *_name;
    encryptionType  _wep;
    waypoint        _wp;
    WaveNet         *_network;
    NSImage         *_netImg;
    NSColor         *_netColor;
	BOOL			_filtered;
	BOOL			_attachedToSuperView;
}

- (id)initWithNetwork:(WaveNet*)network;
- (void)setName:(NSString*)name;
- (void)setWep:(encryptionType)wep;
- (void)setCoord:(waypoint)wp;
- (void)setFiltered:(BOOL)filtered;
- (waypoint)coord;

- (void)align;
- (NSImage*)generateImage;

- (BOOL)removeFromSuperView;

@end
