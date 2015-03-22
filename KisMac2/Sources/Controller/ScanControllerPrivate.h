/*
        
        File:			ScanControllerPrivate.h
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

#import "ScanController.h"

@interface ScanController(PrivateExtension) 

- (void)updatePrefs:(NSNotification*)note;

- (void)updateChannelMenu;

- (void)menuSetEnabled:(bool)a menu:(NSMenu*)menu;
- (void)selectNet:(WaveNet*)net;

- (void)changedViewTo:(__availableTabs)tab contentView:(NSView*)view;
- (void)showDetailsFor:(WaveNet*)net;
- (void)hideDetails;

- (void)startCrackDialog;
- (void)startCrackDialogWithTitle:(NSString*)title stopScan:(BOOL)stopScan;
- (void)startCrackDialogWithTitle:(NSString*)title;
- (bool)startActiveAttack;
- (void)stopActiveAttacks;

- (void)clearAreaMap;
- (void)advNetViewInvalid:(NSNotification*)note;
- (void)networkAdded:(NSNotification*)note;
- (void)refreshScanHierarch;

- (void)showBusyWithText:(NSString*)title andEndSelector:(SEL)didEndSelector andDialog:(NSString*)dialog;
- (void)showBusyWithText:(NSString*)title;
- (void)busyDone;
- (void)modalDone:(NSNotification*)note;
- (void)showBusy:(SEL)function withArg:(id)obj;

- (void)showWantToSaveDialog:(SEL)overrideFunction;
- (void)showExportFailureDialog;
- (void)showSavingFailureDialog;
- (void)showAlreadyCrackedDialog;
- (void)showWrongEncryptionType;
- (void)showNeedMorePacketsDialog;
- (void)showNeedMoreWeakPacketsDialog;
- (void)showNeedToRevealSSID;

@end
