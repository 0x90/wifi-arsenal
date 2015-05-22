//
//  BINSExtensions.m
//  BIGeneric
//
//  Created by mick on Tue Jul 13 2004.
//  Copyright (c) 2004 __MyCompanyName__. All rights reserved.
//

#import "BINSExtensions.h"

static BOOL _alertDone;

@implementation NSWindow(BIExtension) 

- (void)alertSheetDidEnd:(NSWindow *)sheet returnCode:(int)returnCode contextInfo:(void *)contextInfo {
    _alertDone = YES;
}

- (int)showAlertMessage:(NSString *)msg title:(NSString *)title button:(NSString *)button {
    NSAlert *alert;
    
    alert = [[NSAlert alloc] init];
    alert.messageText = title;
    alert.informativeText = msg;
    
    [alert addButtonWithTitle:button];
    [alert setAlertStyle:NSCriticalAlertStyle];
    
    __weak typeof(self) weakSelf = self;
    [alert beginSheetModalForWindow:self completionHandler:^(NSModalResponse returnCode) {
        [weakSelf alertSheetDidEnd:weakSelf returnCode:returnCode contextInfo:nil];
    }];
    
    return 0;
}

@end

@implementation NSString(BIExtension) 

- (NSString*)standardPath
{
    NSMutableString *path;
    
    if ([self length] > 2 && [[self substringToIndex:2] isEqualToString:@"/:"]) {
        path = [NSMutableString stringWithString:[self substringFromIndex:1]];
        [path replaceOccurrencesOfString:@"/" withString:@">" options:0 range:NSMakeRange(0, [path length])];
        [path replaceOccurrencesOfString:@":" withString:@"/" options:0 range:NSMakeRange(0, [path length])];
        [path replaceOccurrencesOfString:@">" withString:@":" options:0 range:NSMakeRange(0, [path length])];
        
        return path;
    } else return [self stringByStandardizingPath];
}

@end


@implementation NSNotificationCenter(BIExtension) 

+ (void)postNotification:(NSString*)notificationName {
    [[NSNotificationCenter defaultCenter] postNotificationName:notificationName object:nil];
}

@end

@implementation NSObject(BIExtension) 

- (void)unsubscribeNotifications {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}

@end

@implementation NSThread(BIExtension) 

+ (void)sleep:(NSTimeInterval)seconds {
    [NSThread sleepUntilDate:[NSDate dateWithTimeIntervalSinceNow:seconds]];
}

@end