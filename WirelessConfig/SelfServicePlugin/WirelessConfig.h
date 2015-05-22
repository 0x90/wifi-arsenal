//
//  WirelessConfig.h
//  WirelessConfig
//
//  Created by Zack Smith on 2/10/12.
//  Copyright 2012 318 All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "SSPluginProtocol.h"

@class GlobalStatus;


@interface WirelessConfig : NSViewController <SSRootAccessProtocol> {
	// IBOutlets
	IBOutlet NSTextField *userNameField;
	IBOutlet NSSecureTextField *passWordField;
	IBOutlet NSButton *mainButton;
	IBOutlet NSProgressIndicator *mainProgressIndicator;
	IBOutlet NSBox *credentialsBox;
	
	IBOutlet NSTextField *mainTitle;
	IBOutlet NSTextField *mainSubTitle;
	
	NSDictionary *settings;
	NSBundle *mainBundle;

	// Properties
	NSString *userName;
	NSString *passWord;
	
	id rootObject;

	// Custom Class instance variables
	GlobalStatus  *globalStatusController;

	// Global status arrays
	NSMutableArray *globalStatusArray;
	
	BOOL debugEnabled;
	BOOL scriptRunning;
	BOOL hideCredentialsFields;
}


// Init Methods
- (void)readInSettings;


//Protocol Methods
- (NSImage *) image;
- (NSString *) subtitle;
- (NSURL *) url;
- (NSString *) pluginID;
- (id) initWithBundle:(NSBundle *)bundle;
- (void)viewWillAppear;
- (void)viewDidAppear;
- (void)receivedStdout:(NSString *)text;
- (void)receivedStderr:(NSString *)text;
- (void)determineRunMode;

- (void)runScript:(id)sender;

- (void)updateTable;
- (void)displaySetupComplete:(id)sender;

// IBActions
-(IBAction)connectButtonClicked:(id)sender;

// Fields
@property (retain) NSString* userName;
@property (retain) NSDictionary* settings;

@property (retain) NSString* passWord;
@property BOOL scriptRunning;

@property BOOL hideCredentialsFields;

@end

