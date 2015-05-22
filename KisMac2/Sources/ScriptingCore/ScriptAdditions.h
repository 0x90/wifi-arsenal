/*
        
        File:			ScriptAdditions.h
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


@interface NSApplication (APLApplicationExtensions)

- (id)showNetworks:(NSScriptCommand *)command;
- (id)showTraffic:(NSScriptCommand *)command;
- (id)showMap:(NSScriptCommand *)command;
- (id)showDetails:(NSScriptCommand *)command;

- (id)startScan:(NSScriptCommand *)command;
- (id)stopScan:(NSScriptCommand *)command;

- (id)new:(NSScriptCommand *)command;
- (id)save:(NSScriptCommand *)command;
- (id)saveAs:(NSScriptCommand *)commandMark;
- (id)importKisMAC:(NSScriptCommand *)command;
- (id)importImageForMap:(NSScriptCommand *)command;
- (id)importPCAP:(NSScriptCommand *)command;
- (id)exportKML:(NSScriptCommand *)command;
- (id)downloadMap:(NSScriptCommand*)command;

- (id)selectNetworkAtIndex:(NSScriptCommand *)command;
- (id)selectNetworkWithBSSID:(NSScriptCommand *)command;

- (id)bruteforceNewsham:(NSScriptCommand *)command;
- (id)bruteforce40bitLow:(NSScriptCommand *)command;
- (id)bruteforce40bitAlpha:(NSScriptCommand *)command;
- (id)bruteforce40bitAll:(NSScriptCommand *)command;

- (id)wordlist40bitApple:(NSScriptCommand *)command;
- (id)wordlist104bitApple:(NSScriptCommand *)command;
- (id)wordlist104bitMD5:(NSScriptCommand *)command;

- (id)wordlistWPA:(NSScriptCommand *)command;
- (id)wordlistLEAP:(NSScriptCommand *)command;

- (id)weakSchedulingAttack:(NSScriptCommand *)command;

- (id)showNetworksInMap:(NSScriptCommand*)command;
- (id)showTraceInMap:(NSScriptCommand*)command;
- (id)setCurrentPosition:(NSScriptCommand*)command;
- (id)setWaypoint:(NSScriptCommand*)command;

- (id)busy:(NSScriptCommand *)command;

@end