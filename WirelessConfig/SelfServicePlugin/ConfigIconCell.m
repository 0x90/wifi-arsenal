//
//  ConfigIconCell.m
//  WirelessConfig
//
//  Created by Zack Smith on 8/19/11.
//  Copyright 2011 wallcity.org All rights reserved.
//

#import "ConfigIconCell.h"
#import "Constants.h"


@implementation ConfigIconCell

# pragma mark -
# pragma mark Method Overrides
# pragma mark -

- (id)init
{	
	[super init];
	[self readInSettings];
	if(debugEnabled)NSLog(@"DEBUG: (init) OK Status Icon Cell Controller Initialized");
	// And Return
	if (!self) return nil;
    return self;
}


- (void) setDataDelegate: (NSObject*) aDelegate {
	[aDelegate retain];	
	[delegate autorelease];
	delegate = aDelegate;	
}


- (id) dataDelegate {
	if (delegate) return delegate;
	return self; // in case there is no delegate we try to resolve values by using key paths
}

# pragma mark -
# pragma mark Class Methods
# pragma mark -

- (void)readInSettings 
{ 	
	mainBundle = [NSBundle bundleForClass:[self class]];
	NSString *settingsPath = [mainBundle pathForResource:SettingsFileResourceID
												  ofType:@"plist"];
	settings = [[NSDictionary alloc] initWithContentsOfFile:settingsPath];
	
	debugEnabled = [[settings objectForKey:@"debugEnabled"] boolValue];
}

- (void)drawWithFrame:(NSRect)cellFrame inView:(NSView *)controlView
{
	
	if(debugEnabled)NSLog(@"(drawWithFrame) Composing image and text...");

	[self setTextColor:[NSColor blackColor]];
		
	NSDictionary* data = [self objectValue];
	if (!data) {
		if(debugEnabled)NSLog(@"(drawWithFrame) No data object");
		return;

	}

	BOOL elementDisabled    = NO;	

	
	NSColor* primaryColor   = [self isHighlighted] ? [NSColor alternateSelectedControlTextColor] : (elementDisabled? [NSColor disabledControlTextColor] : [NSColor textColor]);

	NSString* primaryText;
	if ([data objectForKey:@"title"] !=nil) {
		if(debugEnabled)NSLog(@"(drawWithFrame) Found title: %@",[data objectForKey:@"title"]);

		primaryText = [data objectForKey:@"title"];
	}
	else {
		if(debugEnabled)NSLog(@"(drawWithFrame) No title setting to default");
		primaryText   = @"Unknown";
	}
	
	NSDictionary* primaryTextAttributes = [NSDictionary dictionaryWithObjectsAndKeys: primaryColor, NSForegroundColorAttributeName,
										   [NSFont systemFontOfSize:13], NSFontAttributeName, nil];	
	[primaryText drawAtPoint:NSMakePoint(cellFrame.origin.x+cellFrame.size.height+10, cellFrame.origin.y) withAttributes:primaryTextAttributes];
	
	NSColor* secondaryColor = [self isHighlighted] ? [NSColor alternateSelectedControlTextColor] : [NSColor disabledControlTextColor];
	
	
	NSString* secondaryText;
	if ([data objectForKey:@"reason"] !=nil) {
		if(debugEnabled)NSLog(@"DEBUG: (drawWithFrame) Found reason: %@",[data objectForKey:@"reason"]);

		secondaryText = [data objectForKey:@"reason"];
	}
	else {
		if(debugEnabled)NSLog(@"DEBUG: (drawWithFrame) No reason setting to default");
		secondaryText   = @"Unknown";
	}


	
	NSDictionary* secondaryTextAttributes = [NSDictionary dictionaryWithObjectsAndKeys: secondaryColor, NSForegroundColorAttributeName,
											 [NSFont systemFontOfSize:10], NSFontAttributeName, nil];	
	[secondaryText drawAtPoint:NSMakePoint(cellFrame.origin.x+cellFrame.size.height+10, cellFrame.origin.y+cellFrame.size.height/2) 
				withAttributes:secondaryTextAttributes];
	
	
	[[NSGraphicsContext currentContext] saveGraphicsState];
	float yOffset = cellFrame.origin.y;
	if ([controlView isFlipped]) {
		NSAffineTransform* xform = [NSAffineTransform transform];
		[xform translateXBy:0.0 yBy: cellFrame.size.height];
		[xform scaleXBy:1.0 yBy:-1.0];
		[xform concat];		
		yOffset = 0-cellFrame.origin.y;
	}
	
	// Grab the Icon at the specified Path
	NSString* iconPath;
	if ([data objectForKey:@"image"] !=nil) {
		if(debugEnabled)NSLog(@"DEBUG: (drawWithFrame) Found image: %@",[data objectForKey:@"image"]);
		
		iconPath = [data objectForKey:@"image"];
	}
	else {
		if(debugEnabled)NSLog(@"DEBUG: (drawWithFrame) No Found image setting to default");
		
		iconPath   = @"WirelessConfig";
	}

	NSImage *icon = [[NSImage alloc] initWithContentsOfFile: [ mainBundle pathForResource:iconPath
																				   ofType:@"png"]];
	
	NSImageInterpolation interpolation = [[NSGraphicsContext currentContext] imageInterpolation];
	[[NSGraphicsContext currentContext] setImageInterpolation: NSImageInterpolationHigh];	
	
	[icon drawInRect:NSMakeRect(cellFrame.origin.x+5,yOffset+3,cellFrame.size.height-6, cellFrame.size.height-6)
			fromRect:NSMakeRect(0,0,[icon size].width, [icon size].height)
		   operation:NSCompositeSourceOver
			fraction:1.0];
	
	[[NSGraphicsContext currentContext] setImageInterpolation: interpolation];
	
	[[NSGraphicsContext currentContext] restoreGraphicsState];
}


@end
