/*
        
        File:			ScanControllerScriptable.h
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
#import <Foundation/Foundation.h>
#import "ScanController.h"

@interface ScanController(ScriptableAdditions)

- (BOOL)isSaved;
- (NSString*)filename;
- (WaveNet*)selectedNetwork;

- (BOOL)showNetworks;
- (BOOL)showTrafficView;
- (BOOL)showMap;
- (BOOL)showDetails;

- (BOOL)toggleScan;
- (BOOL)startScan;
- (BOOL)stopScan;

- (BOOL)new;
- (BOOL)open:(NSString*)filename;
- (BOOL)importKisMAC:(NSString*)filename;
- (BOOL)importImageForMap:(NSString*)filename;
- (BOOL)importPCAP:(NSString*)filename;
- (BOOL)exportKML:(NSString*)filename;
- (BOOL)downloadMapFrom:(NSString*)server forPoint:(waypoint)w resolution:(NSSize)size zoomLevel:(int)zoom;
- (BOOL)save:(NSString*)filename;
- (BOOL)saveAs:(NSString*)filename;

- (BOOL)selectNetworkWithBSSID:(NSString*)BSSID;
- (BOOL)selectNetworkAtIndex:(NSNumber*)index;
- (int) networkCount;

- (BOOL)isBusy;

- (BOOL)bruteforceNewsham;
- (BOOL)bruteforce40bitLow;
- (BOOL)bruteforce40bitAlpha;
- (BOOL)bruteforce40bitAll;

- (BOOL)wordlist40bitApple:(NSString*)wordlist;
- (BOOL)wordlist104bitApple:(NSString*)wordlist;
- (BOOL)wordlist104bitMD5:(NSString*)wordlist;
- (BOOL)wordlistWPA:(NSString*)wordlist;
- (BOOL)wordlistLEAP:(NSString*)wordlist;

- (BOOL)weakSchedulingAttackForKeyLen:(int)keyLen andKeyID:(int)keyID;

@end

BOOL saveAllNets;