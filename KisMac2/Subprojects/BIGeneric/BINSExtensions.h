//
//  BINSExtensions.h
//  BIGeneric
//
//  Created by mick on Tue Jul 13 2004.
//  Copyright (c) 2004 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>

@interface NSWindow(BIExtension) 

- (int)showAlertMessage:(NSString *)msg title:(NSString *)title button:(NSString *)button;

@end

@interface NSString(BIExtension) 

- (NSString*)standardPath;

@end

@interface NSNotificationCenter(BIExtension) 

+ (void)postNotification:(NSString*)notificationName;

@end

@interface NSObject(BIExtension) 

- (void)unsubscribeNotifications;

@end

@interface NSThread(BIExtension) 

+ (void)sleep:(NSTimeInterval)seconds;

@end
