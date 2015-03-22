//
//  GlobalStatus.m
//  WirelessConfig
//
//  Created by Zack Smith on 11/29/11.
//  Copyright 2011 wallcity.org All rights reserved.
//

#import "GlobalStatus.h"
#import "Constants.h"


@implementation GlobalStatus

#pragma mark Method Overides
-(id)init
{
    [ super init];
	if(debugEnabled)NSLog(@"Init OK Global Status Controller Initialized");
	[[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(notifRequestStatusUpdateNotification:) 
                                                 name:RequestStatusUpdateNotification
                                               object:nil];
	
	// Plugin -> GlobalStatus
	[[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(notifStatusUpdateNotification:) 
                                                 name:StatusUpdateNotification
                                               object:nil];
	
	if (!globalStatusArray) {
		globalStatusArray = [[NSMutableArray alloc] init];
	}
	
	[self readInSettings];
	
	// And Return
	if (!self) return nil;
    return self;
}

-(void)dealloc 
{ 
	// Remove observer for window close
	[[NSNotificationCenter defaultCenter] removeObserver:self];
	
	//[self.globalStatusArray release];
	[super dealloc]; 
}


- (void)readInSettings 
{ 	
	mainBundle = [NSBundle bundleForClass:[self class]];
	NSString *settingsPath = [mainBundle pathForResource:SettingsFileResourceID
												  ofType:@"plist"];
	settings = [[NSDictionary alloc] initWithContentsOfFile:settingsPath];
	
	debugEnabled = [[settings objectForKey:@"debugEnabled"] boolValue];
}

#pragma mark -
#pragma mark Notifications Methods
#pragma mark -

- (void) notifRequestStatusUpdateNotification:(NSNotification *) notification
{
	NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
	if(debugEnabled)NSLog(@"DEBUG: Request Status Update Notification Received");
	
	NSMutableDictionary *globalStatusUpdate = [[NSMutableDictionary alloc] init];
	
	[ globalStatusUpdate setValue:globalStatusArray forKey:@"globalStatusArray"];
	
	// Post the current Data to our NSTable via userInfo
	[[NSNotificationCenter defaultCenter]
	 postNotificationName:ReceiveStatusUpdateNotification
	 object:self
	 userInfo:globalStatusUpdate];
	
	if(debugEnabled)NSLog(@"DEBUG: Recieved Request to Send Complete Global Status Array");
	[pool release];
}

- (void) notifStatusUpdateNotification:(NSNotification *) notification
{
	// Add the status item to the Array
	NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
	
	if(debugEnabled)NSLog(@"DEBUG: (notifStatusUpdateNotification) Status Update Notification Received");
	
	NSDictionary *globalStatusUpdate = [notification userInfo];
	
	if(debugEnabled)NSLog(@"DEBUG: (notifStatusUpdateNotification) Recieved New Global Status: %@",globalStatusUpdate);

	[globalStatusArray addObjectsFromArray:[globalStatusUpdate objectForKey:@"globalStatusArray"]];
	
	if(debugEnabled)NSLog(@"DEBUG: (notifStatusUpdateNotification) Global Array Status Update: %@",globalStatusArray);
	
	// Post the current Data to our NSTable via userInfo
	[[NSNotificationCenter defaultCenter]
	 postNotificationName:ReceiveStatusUpdateNotification
	 object:self
	 userInfo:globalStatusUpdate];
	
	 [pool release];
}


@end
