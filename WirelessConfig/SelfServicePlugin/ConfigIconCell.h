//
//  ConfigIconCell.h
//  WirelessConfig
//
//  Created by Zack Smith on 8/19/11.
//  Copyright 2011 wallcity.org All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "Constants.h"

@interface ConfigIconCell : NSTextFieldCell {
	NSObject* delegate;

	// Standard iVars
	NSBundle *mainBundle;
	NSDictionary *settings;
	BOOL debugEnabled;

	
}

- (void)readInSettings ;
- (void) setDataDelegate: (NSObject*) aDelegate;


@end
