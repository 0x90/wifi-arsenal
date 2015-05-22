//
//  BIZoomView.h
//  BIGeneric
//
//  Created by mick on Sat Jul 03 2004.
//  Copyright (c) 2004 __MyCompanyName__. All rights reserved.
//

#import <AppKit/AppKit.h>
#import <BIGL/BIGL.h>

@interface BIZoomView : BIGLView {
    NSView *_view;
    BIGLImageView *_v1, *_v2;
}

- (void)zoomFrom:(NSView*)oldV to:(NSView*)newV;
- (void)cleanUpZoom;
@end
