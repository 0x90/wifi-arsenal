/*
        
        File:			WaveStorageController.h
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

@class WaveContainer;
@class ImportController;

@interface WaveStorageController : NSObject {

}

//functions for loading and saving etc
+ (BOOL)importFromFile:(NSString*)filename withContainer:(WaveContainer*)container andImportController:(ImportController*)im;
+ (BOOL)loadFromFile:(NSString*)filename withContainer:(WaveContainer*)container andImportController:(ImportController*)im;

+ (BOOL)importFromNetstumbler:(NSString*)filename withContainer:(WaveContainer*)container andImportController:(ImportController*)im;
+ (NSString*)webServiceDataOfContainer:(WaveContainer*)container andImportController:(ImportController*)im;

+ (BOOL)saveToFile:(NSString*)filename withContainer:(WaveContainer*)container andImportController:(ImportController*)im;
+ (BOOL)exportNSToFile:(NSString*)filename withContainer:(WaveContainer*)container andImportController:(ImportController*)im;
+ (BOOL)exportKMLToFile:(NSString*)filename withContainer:(WaveContainer*)container andImportController:(ImportController*)im;
+ (BOOL)exportMacStumblerToFile:(NSString*)filename withContainer:(WaveContainer*)container andImportController:(ImportController*)im;

@end
