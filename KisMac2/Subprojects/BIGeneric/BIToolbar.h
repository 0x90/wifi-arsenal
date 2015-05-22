//
//  BIToolbar.h
//  BIGeneric
//
//  Created by mick on Fri Jul 02 2004.
//  Copyright (c) 2004 __MyCompanyName__. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#import "NSToolbar.h"

@interface BIToolbar : NSToolbar {
}

- (void)_setToolbarView:(id)view;

@end