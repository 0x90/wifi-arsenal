//
//  BIToolbar.m
//  BIGeneric
//
//  Created by mick on Fri Jul 02 2004.
//  Copyright (c) 2004 __MyCompanyName__. All rights reserved.
//

#import "BIToolbar.h"
#import "BIToolbarView.h"

@implementation BIToolbar

- (id)initWithIdentifier:(NSString *)identifier {
    self = [super initWithIdentifier:identifier];
    if (!self) return nil;
    
    [self setAllowsUserCustomization:NO];
    
    return self;
}

- (void)_setToolbarView:(id)view {
    BIToolbarView *b = [[BIToolbarView alloc] initWithFrame:NSMakeRect(0,0,1000,1000)];
    [view addSubview:b positioned:NSWindowBelow relativeTo:nil];
    [super _setToolbarView:view];
}

@end
