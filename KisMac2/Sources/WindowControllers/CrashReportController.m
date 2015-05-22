/*
        
        File:			CrashReporter.m
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

#import "CrashReportController.h"
#import <AddressBook/ABAddressBook.h>
#import <AddressBook/ABPerson.h>
#import <AddressBook/ABMultiValue.h>
#import "KisMACNotifications.h"
#import "WaveHelper.h"

static const CFOptionFlags kNetworkEvents = kCFStreamEventOpenCompleted |
                                            kCFStreamEventHasBytesAvailable |
                                            kCFStreamEventEndEncountered |
                                            kCFStreamEventErrorOccurred;

static void
ReadStreamClientCallBack(CFReadStreamRef stream, CFStreamEventType type, void *clientCallBackInfo) {
    // Pass off to the object to handle.
    [((__bridge CrashReportController*)clientCallBackInfo) handleNetworkEvent: type];
}

@implementation CrashReportController

- (void)awakeFromNib
{
    ABPerson *me;
    ABMultiValue *mails;
    NSString *value;
    me = [[ABAddressBook sharedAddressBook] me];

    [[self window] setDelegate:self];
    
    if (me) {
        mails = [me valueForProperty:kABEmailProperty]; 
        value = [mails valueAtIndex:[mails indexForIdentifier:[mails primaryIdentifier]]];
        [_mail setStringValue:value];
    }
}

- (void)setReport:(NSData*)data 
{
    NSRange endRange;

    endRange.location = [[_report textStorage] length];
    endRange.length = 0;
    [_report replaceCharactersInRange:endRange withString:[NSString stringWithCString:[data bytes] encoding:NSUTF8StringEncoding]];
}

- (IBAction)allowAction:(id)sender 
{
    CFHTTPMessageRef request;
    CFStreamClientContext ctxt = {0, (__bridge void *)(self), NULL, NULL, NULL};
    NSURL* url;
    NSData* data;
    NSString *errstr;
    NSMutableString* topost;
    
    [_allow setEnabled:NO];
    [_deny setEnabled:NO];
    [_alwaysDeny setEnabled:NO];
    
    // Create a new url based upon the user entered string
    url = [NSURL URLWithString: @"http://kismac-ng.org/crash.php"];
    	
    // Get data for POST body
    topost = [NSMutableString string];
    [topost appendFormat:@"report=%@", [WaveHelper urlEncodeString:[_report string]]];
    [topost appendFormat:@"&comment=%@", [WaveHelper urlEncodeString:[_comment string]]];
    [topost appendFormat:@"&mail=%@", [WaveHelper urlEncodeString:[_mail stringValue]]];
    [topost appendFormat:@"&version=%@", [WaveHelper urlEncodeString:[[[NSBundle mainBundle] infoDictionary] valueForKey:@"CFBundleShortVersionString"]]];
    [topost appendFormat:@"&date=%@", [WaveHelper urlEncodeString:[NSString stringWithFormat:@"%s %s", __DATE__, __TIME__]]];
    
    data = [topost dataUsingEncoding: NSUTF8StringEncoding];
    
    // Create a new HTTP request.
    request = CFHTTPMessageCreateRequest(kCFAllocatorDefault, CFSTR("POST"), (__bridge CFURLRef)url, kCFHTTPVersion1_0);
    
    // Set the body.
    CFHTTPMessageSetBody(request, (__bridge CFDataRef)data);
    CFHTTPMessageSetHeaderFieldValue(request,CFSTR("Content-Type"),CFSTR("application/x-www-form-urlencoded"));
        
    // Create the stream for the request.
    _stream = CFReadStreamCreateForHTTPRequest(kCFAllocatorDefault, request);
    
    // Release the request.  The fetch should've retained it if it
    // is performing the fetch.
    CFRelease(request);

    // Make sure it succeeded.
	bool wasError = false;
    if (!_stream) {
        errstr = NSLocalizedString(@"Creating the stream failed.", "Error for Crashreporter");
        wasError = true;
    }
    
    // Set the client
    if (!wasError && !CFReadStreamSetClient(_stream, kNetworkEvents, ReadStreamClientCallBack, &ctxt)) {
        CFRelease(_stream);
        _stream = NULL;
        errstr = NSLocalizedString(@"Setting the stream's client failed.", "Error for Crashreporter");
        wasError = true;
    }
    
	if (!wasError) {
		CFReadStreamScheduleWithRunLoop(_stream, CFRunLoopGetCurrent(), kCFRunLoopCommonModes);
		
		// Start the HTTP connection
		if (!CFReadStreamOpen(_stream)) {
			CFReadStreamSetClient(_stream, 0, NULL, NULL);
			CFReadStreamUnscheduleFromRunLoop(_stream, CFRunLoopGetCurrent(), kCFRunLoopCommonModes);
			CFRelease(_stream);
			_stream = NULL;
			errstr = NSLocalizedString(@"Opening the stream failed.", "Error for Crashreporter");
			wasError = true;
		}
	}
    // Schedule the stream
    
	if (!wasError) {
		return;
	}
    
    NSBeginCriticalAlertSheet(
        NSLocalizedString(@"Transmittion failed.", "Title for Crashreporter"),
        OK, NULL, NULL, [self window], self, NULL, NULL, NULL,
        [NSString stringWithFormat:@"%@: %@", 
        NSLocalizedString(@"The transmittion of the report failed because of the following error", "Dialog text for Crashreporter"), 
        errstr], nil);
    [_allow setEnabled:YES];
    [_deny setEnabled:YES];
    [_alwaysDeny setEnabled:YES];
}

- (IBAction)denyAction:(id)sender 
{
    NSString* crashPath;
    NSFileManager *mang;
    NSString * logPath;
    NSDirectoryEnumerator * enumerator;
    
    logPath = [@"~/Library/Logs/DiagnosticReports/" stringByExpandingTildeInPath];
    mang = [NSFileManager defaultManager];
    
    enumerator = [mang enumeratorAtPath: logPath];
    
    //find all the crash logs and turn them into one big data blob
    for(NSString * file in enumerator)
    {
        if([file hasPrefix:@"KisMAC"])
        {
            crashPath = [NSString stringWithFormat:@"%@/%@", logPath, file];
            DBNSLog(@"Removing crash log at: %@", crashPath);
            [mang removeItemAtPath:crashPath error:nil];
        }
    }
    
    [[self window] performClose:nil];
}

- (IBAction)alwaysDenyAction:(id)sender
{
    [[NSUserDefaults standardUserDefaults] setInteger:1 forKey:@"SupressCrashReport"]; 
    [[self window] performClose:nil];
}

- (void)handleNetworkEvent:(CFStreamEventType)type 
{    
    // Dispatch the stream events.
    switch (type) {
        case kCFStreamEventHasBytesAvailable:
            [self handleBytesAvailable];
            break;
            
        case kCFStreamEventEndEncountered:
            [self handleStreamComplete];
            break;
            
        case kCFStreamEventErrorOccurred:
            [self handleStreamError];
            break;
            
        default:
            break;
    }
}


- (void)handleBytesAvailable
{

    UInt8 buffer[2048];
    CFIndex bytesRead = CFReadStreamRead(_stream, buffer, sizeof(buffer));
    
    // Less than zero is an error
    if (bytesRead < 0)
    {
        [self handleStreamError];
    }
}


- (void)terminateit:(NSWindow *)sheet returnCode:(int)returnCode contextInfo:(void *)contextInfo 
{
    [self denyAction:nil];
}

- (void)handleStreamComplete
{
    // Don't need the stream any more, and indicate complete.
    CFReadStreamSetClient(_stream, 0, NULL, NULL);
    CFReadStreamUnscheduleFromRunLoop(_stream, CFRunLoopGetCurrent(), kCFRunLoopCommonModes);
    CFReadStreamClose(_stream);
    CFRelease(_stream);
    _stream = NULL;
    NSBeginInformationalAlertSheet(
        NSLocalizedString(@"Transmittion complete.", "Title for Crashreporter"),
        OK, NULL, NULL, [self window], self, NULL, @selector(terminateit:returnCode:contextInfo:), (__bridge void *)(self),
        NSLocalizedString(@"The transmittion of the report is complete. Thank you for your help!", "Dialog text for Crashreporter"));
}


- (void)handleStreamError
{
    CFStreamError error = CFReadStreamGetError(_stream);

    // Lame error handling.  Simply state that an error did occur.
    CFReadStreamSetClient(_stream, 0, NULL, NULL);
    CFReadStreamUnscheduleFromRunLoop(_stream, CFRunLoopGetCurrent(), kCFRunLoopCommonModes);
    CFReadStreamClose(_stream);
    CFRelease(_stream);
    _stream = NULL;
    
    NSBeginCriticalAlertSheet(
        NSLocalizedString(@"Transmittion failed.", "Title for Crashreporter"),
        OK, NULL, NULL, [self window], self, NULL, NULL, NULL, 
        [NSString stringWithFormat:@"%@: %ld, %d", 
        NSLocalizedString(@"The transmittion of the report failed because of the following error", "Dialog text for Crashreporter"), 
        error.domain, error.error], nil);
    [_allow setEnabled:YES];
    [_deny setEnabled:YES];
    [_alwaysDeny setEnabled:YES];
}

- (void)windowWillClose:(NSNotification *)aNotification 
{
    [[NSNotificationCenter defaultCenter] postNotificationName:KisMACModalDone object:self];
}

#pragma mark Fade Out Code

- (BOOL)windowShouldClose:(id)sender
{
    // Set up our timer to periodically call the fade: method.
    [NSTimer scheduledTimerWithTimeInterval:0.05 target:self selector:@selector(fade:) userInfo:nil repeats:YES];
    
    return NO;
}

- (void)fade:(NSTimer *)timer 
{
    if ([[self window] alphaValue] > 0.0) 
    {
        // If window is still partially opaque, reduce its opacity.
        [[self window] setAlphaValue:[[self window] alphaValue] - 0.2];
    } 
    else 
    {
        // Otherwise, if window is completely transparent, destroy the timer and close the window.
        [timer invalidate];
        
        [[self window] close];
        
        // Make the window fully opaque again for next time.
        [[self window] setAlphaValue:1.0];
    }
}
@end
