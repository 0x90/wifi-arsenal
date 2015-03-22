//
//  BIGLCocoaView.h
//  BIGL
//
//  Created by mick on Thu Jul 08 2004.
//  Copyright (c) 2004 __MyCompanyName__. All rights reserved.
//

#import <AppKit/AppKit.h>


@interface BIGLCocoaView : NSView {
    NSColor *_color;
    NSArray *_subs;
}

- (void)setSubViews:(NSArray*)subs;
- (void)setBackgroundColor:(NSColor*)color;

@end
