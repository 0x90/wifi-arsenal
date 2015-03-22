/*
        
        File:			ScriptController.m
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

#import "ScriptController.h"
#import "ScanController.h"
#import "ScanControllerPrivate.h"
#import "ScanControllerScriptable.h"
#import "WaveHelper.h"
#import "ScriptAdditions.h"
#import "KisMACNotifications.h"
#import "ScriptingEngine.h"
#import "WaveNet.h"

@implementation ScriptController

- (id)init
{
    self = [super init];
    if (!self) return nil;
    
    [[NSNotificationCenter defaultCenter] addObserver:self
											 selector:@selector(tryToSave:)
												 name:KisMACTryToSave
											   object:nil];

    return self;
}

- (void)tryToSave:(NSNotification*)note
{
    [self saveKisMACFile:nil];
}

#pragma mark -

- (void)showWantToSaveDialog:(SEL)overrideFunction
{
	NSBeginAlertSheet(
        NSLocalizedString(@"Save Changes?", "Save changes dialog title"),
        NSLocalizedString(@"Save", "Save changes dialog button"),
        NSLocalizedString(@"Don't Save", "Save changes dialog button"),
        CANCEL, [WaveHelper mainWindow], self, NULL, @selector(saveDialogDone:returnCode:contextInfo:), overrideFunction, 
        NSLocalizedString(@"Save changes dialog text", "LONG dialog text")
        );
}

- (void)saveDialogDone:(NSWindow *)sheet returnCode:(int)returnCode contextInfo:(SEL)overrideFunction
{
    switch (returnCode)
    {
    case NSAlertDefaultReturn:
        [self saveKisMACFileAs:nil];
    case NSAlertOtherReturn:
        break;
    case NSAlertAlternateReturn:
    default:
		{
			NSMethodSignature *methodSignature = [self methodSignatureForSelector:overrideFunction];
			NSInvocation *invocation = [NSInvocation invocationWithMethodSignature:methodSignature];
			[invocation setSelector:overrideFunction];
			//[invocation setArgument:&sheet atIndex:2];
			[invocation invoke];
		}
    }
}

#pragma mark -

- (IBAction)showNetworks:(id)sender
{
    [ScriptingEngine selfSendEvent:'KshN'];
}
- (IBAction)showTrafficView:(id)sender
{
    [ScriptingEngine selfSendEvent:'KshT'];
}
- (IBAction)showMap:(id)sender
{
    [ScriptingEngine selfSendEvent:'KshM'];
}
- (IBAction)showDetails:(id)sender
{
    [ScriptingEngine selfSendEvent:'KshD'];
}

- (IBAction)toggleScan:(id)sender
{
	[ScriptingEngine selfSendEvent:'KssS'];
}

#pragma mark -

- (IBAction)new:(id)sender
{
    ScanController *controller = [NSApp delegate];
    
    if ((sender!=self) && (![controller isSaved]))
    {
        [self showWantToSaveDialog:@selector(new:)];
        return;
    }

   [ScriptingEngine selfSendEvent:'KNew'];
}

#pragma mark -

- (IBAction)openKisMACFile:(id)sender {
    
    ScanController *controller = [NSApp delegate];
    
    if ((sender!=self) && (![controller isSaved]))
    {
        [self showWantToSaveDialog:@selector(openKisMACFile:)];
        return;
    }
    
    NSOpenPanel *op = [NSOpenPanel openPanel];
    [op setAllowsMultipleSelection:NO];
    [op setCanChooseFiles:YES];
    [op setCanChooseDirectories:NO];
	[op setAllowedFileTypes:@[@"kismac"]];
	[op beginWithCompletionHandler:^(NSInteger result)
	 {
		 if (result == NSFileHandlingPanelOKButton)
		 {
             [self performSelector:@selector(openPath:) withObject:[[op URL] path] afterDelay:0.1];
             [op close];
		 }
	 }];
}

- (IBAction)openKisMAPFile:(id)sender
{
	NSOpenPanel *op = [NSOpenPanel openPanel];
    [op setAllowsMultipleSelection:NO];
    [op setCanChooseFiles:YES];
    [op setCanChooseDirectories:NO];
	[op setAllowedFileTypes:@[@"kismap"]];
	[op beginWithCompletionHandler:^(NSInteger result)
	 {
		 if (result == NSFileHandlingPanelOKButton)
		 {
             [self performSelector:@selector(openPath:) withObject:[[op URL] path] afterDelay:0.1];
             [op close];
		 }
		 
	 }];
}

- (void)openPath:(NSString*)path
{
    [ScriptingEngine selfSendEvent:'odoc'
                         withClass:'aevt'
               andDefaultArgString:path];
}

#pragma mark -

- (IBAction)importKisMACFile:(id)sender
{
	NSOpenPanel *op = [NSOpenPanel openPanel];
    [op setAllowsMultipleSelection:YES];
    [op setCanChooseFiles:YES];
    [op setCanChooseDirectories:NO];
	[op setAllowedFileTypes:@[@"kismac"]];
	[op beginWithCompletionHandler:^(NSInteger result)
	 {
		 if (result == NSFileHandlingPanelOKButton)
		 {
			 for (int i = 0; i < [[op URLs] count]; ++i) {
				 NSString *file = [[op URLs][i] path];
				 [ScriptingEngine selfSendEvent:'KImK'
						   withDefaultArgString:file];
			 }
		 }
		 
	 }];
}
- (IBAction)importImageForMap:(id)sender
{
    NSOpenPanel *op;

    op = [NSOpenPanel openPanel];
    [op setAllowsMultipleSelection:NO];
    [op setCanChooseFiles:YES];
    [op setCanChooseDirectories:NO];
	[op setAllowedFileTypes:[NSImage imageFileTypes]];
	[op beginWithCompletionHandler:^(NSInteger result)
	 {
		 if (result == NSFileHandlingPanelOKButton)
		 {
			 [ScriptingEngine selfSendEvent:'KImI'
					   withDefaultArgString:[[op URL] path]];
		 }
		 
	 }];
}
- (IBAction)importPCPFile:(id)sender
{
    NSOpenPanel *op = [NSOpenPanel openPanel];
    [op setAllowsMultipleSelection:YES];
    [op setCanChooseFiles:YES];
    [op setCanChooseDirectories:NO];
	[op beginWithCompletionHandler:^(NSInteger result)
	 {
		 if (result == NSFileHandlingPanelOKButton)
		 {
			 for (int i = 0; i < [[op URLs] count]; ++i) {
				 NSString *file = [[op URLs][i] path];
				 [ScriptingEngine selfSendEvent:'KImP'
						   withDefaultArgString:file];
			 }
		 }
		 
	 }];
}

#pragma mark -

- (IBAction)saveKisMACFile:(id)sender
{
    ScanController *controller = [NSApp delegate];
    
    NSString *filename = [controller filename];
    if (!filename)
    {
        [self saveKisMACFileAs:sender];
    }
    else if (![ScriptingEngine selfSendEvent:'save' withClass:'core' andDefaultArgString:filename])
    {
        [controller showSavingFailureDialog];
    }
}

- (IBAction)saveKisMACFileAs:(id)sender
{
    NSSavePanel *sp = [NSSavePanel savePanel];
    [sp setAllowedFileTypes:@[@"kismac"]];
    [sp setCanSelectHiddenExtension:YES];
    [sp setTreatsFilePackagesAsDirectories:NO];
	[sp beginWithCompletionHandler:^(NSInteger result)
	 {
		 if (result == NSFileHandlingPanelOKButton)
		 {
			 if (![ScriptingEngine selfSendEvent:'KsaA'
							withDefaultArgString:[[sp URL] path]])
             {
                 ScanController *controller = [NSApp delegate];
                 [controller showSavingFailureDialog];
             }
		 }
		 
	 }];
}

- (IBAction)saveKisMAPFile:(id)sender
{
    NSSavePanel *sp = [NSSavePanel savePanel];
    [sp setAllowedFileTypes:@[@"kismap"]];
    [sp setCanSelectHiddenExtension:YES];
    [sp setTreatsFilePackagesAsDirectories:NO];
	[sp beginWithCompletionHandler:^(NSInteger result)
	 {
		 if (result == NSFileHandlingPanelOKButton)
		 {
			 if (![ScriptingEngine selfSendEvent:'save'
									   withClass:'core'
							 andDefaultArgString:[[sp URL] path]])
             {
                 ScanController *controller = [NSApp delegate];
				 [controller showSavingFailureDialog];
             }
		 }
		 
	 }];
}

#pragma mark -

- (BOOL) wepCheck
{
    BOOL result = YES;
    ScanController *controller = [NSApp delegate];
    
    if (![controller selectedNetwork])
    {
        NSBeep();
        result = NO;
    }
    if (result && [[controller selectedNetwork] passwordAvailable])
    {
        [controller showAlreadyCrackedDialog];
        result = NO;
    }
    if (result && [[controller selectedNetwork] wep] != encryptionTypeWEP && [[controller selectedNetwork] wep] != encryptionTypeWEP40)
    {
        [controller showWrongEncryptionType];
        result = NO;
    }
    if (result && [[[controller selectedNetwork] cryptedPacketsLog] count] < 8)
    {
        [controller showNeedMorePacketsDialog];
        result = NO;
    }
    
    return result;
}

- (IBAction)bruteforceNewsham:(id)sender
{
    if (![self wepCheck])
    {
        return;
    }
    
    [ScriptingEngine selfSendEvent:'KCBN'];
}

- (IBAction)bruteforce40bitLow:(id)sender
{
    if (![self wepCheck])
    {
        return;
    }
    
    [ScriptingEngine selfSendEvent:'KCBL'];
}

- (IBAction)bruteforce40bitAlpha:(id)sender
{
    if (![self wepCheck])
    {
        return;
    }
    
    [ScriptingEngine selfSendEvent:'KCBa'];
}

- (IBAction)bruteforce40bitAll:(id)sender
{
    if (![self wepCheck])
    {
        return;
    }
    
    [ScriptingEngine selfSendEvent:'KCBA'];
}

#pragma mark -

- (IBAction)wordlist40bitApple:(id)sender
{
    if (![self wepCheck])
    {
        return;
    }
    
    NSOpenPanel *op = [NSOpenPanel openPanel];
    [op setAllowsMultipleSelection:YES];
    [op setCanChooseFiles:YES];
    [op setCanChooseDirectories:NO];
	[op beginWithCompletionHandler:^(NSInteger result)
	 {
		 if (result == NSFileHandlingPanelOKButton)
		 {
			 for (int i = 0; i < [[op URLs] count]; ++i)
				 [ScriptingEngine selfSendEvent:'KCWa'
						   withDefaultArgString:[[op URLs][i] path]];
		 }
		 
	 }];
}

- (IBAction)wordlist104bitApple:(id)sender
{
    if (![self wepCheck])
    {
        return;
    }
    
    NSOpenPanel *op = [NSOpenPanel openPanel];
    [op setAllowsMultipleSelection:YES];
    [op setCanChooseFiles:YES];
    [op setCanChooseDirectories:NO];
	[op beginWithCompletionHandler:^(NSInteger result)
	 {
		 if (result == NSFileHandlingPanelOKButton)
		 {
			 for (int i = 0; i < [[op URLs] count]; ++i)
				 [ScriptingEngine selfSendEvent:'KCWA'
						   withDefaultArgString:[[op URLs][i] path]];
		 }
		 
	 }];
}

- (IBAction)wordlist104bitMD5:(id)sender
{
    if (![self wepCheck])
    {
        return;
    }
    
    NSOpenPanel *op = [NSOpenPanel openPanel];
    [op setAllowsMultipleSelection:YES];
    [op setCanChooseFiles:YES];
    [op setCanChooseDirectories:NO];
	[op beginWithCompletionHandler:^(NSInteger result)
	 {
		 if (result == NSFileHandlingPanelOKButton)
		 {
			 for (int i = 0; i < [[op URLs] count]; ++i)
				 [ScriptingEngine selfSendEvent:'KCWM'
						   withDefaultArgString:[[op URLs][i] path]];
		 }
		 
	 }];
}

- (IBAction)wordlistWPA:(id)sender
{
    ScanController *controller = [NSApp delegate];
    
    if (![controller selectedNetwork])
    {
        NSBeep();
        return;
    }
    if ([[controller selectedNetwork] passwordAvailable])
    {
        [controller showAlreadyCrackedDialog];
        return;
    }
    if (([[controller selectedNetwork] wep] != encryptionTypeWPA) && ([[controller selectedNetwork] wep] != encryptionTypeWPA2 ))
    {
        [controller showWrongEncryptionType];
        return;
    }
	if ([[controller selectedNetwork] SSID] == nil)
    {
        [controller showNeedToRevealSSID];
        return;
    }
	if ([[[controller selectedNetwork] SSID] length] > 32)
    {
        [controller showNeedToRevealSSID];
        return;
    }
	if ([[controller selectedNetwork] capturedEAPOLKeys] == 0)
    {
        [controller showNeedMorePacketsDialog];
        return;
    }

    NSOpenPanel *op = [NSOpenPanel openPanel];
    [op setAllowsMultipleSelection:YES];
    [op setCanChooseFiles:YES];
    [op setCanChooseDirectories:NO];
	[op beginWithCompletionHandler:^(NSInteger result)
	 {
		 if (result == NSFileHandlingPanelOKButton)
		 {
			 for (int i = 0; i < [[op URLs] count]; ++i)
				 [ScriptingEngine selfSendEvent:'KCWW'
						   withDefaultArgString:[[op URLs][i] path]];
		 }
		 
	 }];
}

- (IBAction)wordlistLEAP:(id)sender
{
    ScanController *controller = [NSApp delegate];
    
    if (![controller selectedNetwork])
    {
        NSBeep();
        return;
    }
    if ([[controller selectedNetwork] passwordAvailable])
    {
        [controller showAlreadyCrackedDialog];
        return;
    }
    if ([[controller selectedNetwork] wep] != encryptionTypeLEAP)
    {
        [controller showWrongEncryptionType];
        return;
    }
	if ([[controller selectedNetwork] capturedLEAPKeys] == 0)
    {
        [controller showNeedMorePacketsDialog];
        return;
    }
   
	NSOpenPanel * op = [NSOpenPanel openPanel];
    [op setAllowsMultipleSelection:YES];
    [op setCanChooseFiles:YES];
    [op setCanChooseDirectories:NO];
	[op beginWithCompletionHandler:^(NSInteger result)
	 {
		 if (result == NSFileHandlingPanelOKButton)
		 {
			 for (int i = 0; i < [[op URLs] count]; ++i)
				 [ScriptingEngine selfSendEvent:'KCWL'
						   withDefaultArgString:[[op URLs][i] path]];
		 }
		 
	 }];
}

#pragma mark -

- (IBAction)weakSchedulingAttack40bit:(id)sender
{
    if (![self wepCheck])
    {
        return;
    }
    NSAppleEventDescriptor *keyLen = [NSAppleEventDescriptor descriptorWithInt32:5];
    
    NSDictionary *args = @{[NSString stringWithFormat:@"%d", 'KCKl']: keyLen};
    [ScriptingEngine selfSendEvent:'KCSc' withArgs:args];
}

- (IBAction)weakSchedulingAttack104bit:(id)sender
{
    if (![self wepCheck])
    {
        return;
    }
    [ScriptingEngine selfSendEvent:'KCSc'];
}

- (IBAction)weakSchedulingAttack40And104bit:(id)sender
{
    if (![self wepCheck])
    {
        return;
    }
    NSAppleEventDescriptor *keyLen = [NSAppleEventDescriptor descriptorWithInt32:0xFFFFFF];
    
    NSDictionary *args = @{[NSString stringWithFormat:@"%d", 'KCKl']: keyLen};
    [ScriptingEngine selfSendEvent:'KCSc' withArgs:args];
}

#pragma mark -

- (IBAction)showNetworksInMap:(id)sender
{
    BOOL show = ([sender state] == NSOffState);
    
    [ScriptingEngine selfSendEvent:'KMSN'
					withDefaultArg:[NSAppleEventDescriptor descriptorWithBoolean:show]];
}

- (IBAction)showTraceInMap:(id)sender {
    BOOL show = ([sender state] == NSOffState);
    
    [ScriptingEngine selfSendEvent:'KMST'
					withDefaultArg:[NSAppleEventDescriptor descriptorWithBoolean:show]];
}


#pragma mark -

- (void)dealloc
{
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}

@end
