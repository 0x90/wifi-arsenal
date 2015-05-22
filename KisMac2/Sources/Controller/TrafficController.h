//
//  TrafficController.h
//  KisMAC
//
//  Created by mick on Thu Jul 01 2004.
//  Copyright (c) 2004 __MyCompanyName__. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>

@class WaveNet;
@class WaveContainer;
@class WaveScanner;
@class BIGLView;
@class BIGLLineView;
@class BIGLTextView;
@class BIGLImageView;

#define MAX_YIELD_SIZE (int)1200

@interface TrafficController : NSObject {
    IBOutlet BIGLView       *_view;
    IBOutlet WaveScanner    *_scanner;
    IBOutlet WaveContainer  *_container;
    IBOutlet NSPopUpButton  *_intervalButton;
    IBOutlet NSPopUpButton  *_modeButton;
    
    NSMutableArray          *_graphs;
    
    BIGLLineView            *_grid, *_gridFrame;
    BIGLTextView            *_zeroLabel, *_maxLabel, *_curLabel;
    BIGLImageView           *_legend;
    
    NSLock* zoomLock;

    NSColor *_backgroundColor;

    NSRect graphRect;
    NSTimeInterval scanInterval;
    float vScale;	// used for the vertical scaling of the graph
    float dvScale;	// used for the sweet 'zoom' in/out
    float stepx;	// step for horizontal lines on grid
    float stepy;	// step for vertical lines on grid
    float aMaximum;	// maximum bytes received
    int buffer[MAX_YIELD_SIZE];
    BOOL gridNeedsRedrawn;

    BOOL justSwitchedDataType;
    int _legendMode;
    int length;
    int offset;
    int maxLength;
    int currentMode;
    NSMutableArray* allNets;
    NSArray* colorArray;    
}

- (void)updateSettings:(NSNotification*)note;
- (void)outputTIFFTo:(NSString*)file;

- (IBAction)setTimeLength:(id)sender;
- (IBAction)setCurrentMode:(id)sender;

- (void)setBackgroundColor:(NSColor *)newColor;
- (void)setGridColor:(NSColor *)newColor;

- (void)updateGraph;
- (void)updateDataForRect:(NSRect)rect;
- (void)drawGraphInRect:(NSRect)rect;
- (void)drawGridInRect:(NSRect)rect;
- (void)drawGridLabelForRect:(NSRect)rect;
- (void)drawLegendForRect:(NSRect)rect;

- (NSString*)stringForNetwork:(WaveNet*)net;
- (NSString*)stringForBytes:(int)bytes;
- (NSString*)stringForPackets:(int)bytes;
- (NSString*)stringForSignal:(int)bytes;

@end

