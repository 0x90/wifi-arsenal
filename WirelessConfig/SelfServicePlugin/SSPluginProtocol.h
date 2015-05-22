//  SSPluginProtocol.h
//  Copyright 2011 JAMF Software. All rights reserved.

/*
 Self Service Plugin Protocol
 To become a Self Service Plugin, the principal class of your
 Bundle must conform to this protocol
*/

#define JAMFReloadPluginNotification @"JAMFReloadPluginNotification"
#define JAMFPluginViewWidth 1026
#define JAMFPluginViewHeight 550

@protocol SSRootAccessDelegate

- (void) receivedStdout:(NSString *)text;
- (void) receivedStderr:(NSString *)text;

@end

@protocol SSRootAccessProtocol

//Returns nil if no errors are found
-(NSError *) runTask: (NSString *) task withArguments: (NSArray *) args withDelegate:(id<SSRootAccessDelegate>) delegate; 

@end

@protocol SSPluginProtocol

@required
-(NSView *) view;
-(NSImage *) image;
-(NSString *) title;
-(NSString *) subtitle;
-(NSURL *) url;
-(NSString *) pluginID;
-(void) viewWillAppear;
-(void) viewDidAppear;
- (id) initWithBundle:(NSBundle *)bundle;

@optional
-(void) setView: (NSView *) object;
-(void) setImage: (NSImage *) object;
-(void) setTitle: (NSString *) object;
-(void) setSubtitle: (NSString *) object;
-(void) setUrl: (NSURL *) object;
-(BOOL) shouldDisplay;
-(BOOL) supportsBackgrounding;
-(BOOL) openInBrowserAutomatically;

//NSMenu for click
-(NSMenu*) menuForRightClickWithEvent:(NSEvent *) event;

//Responses to the Navigation control
-(void) navigationConrtolBackClicked;
-(void) navigationConrtolForwardClicked;
-(void) navigationConrtolHomeClicked;

//Response to search bar
-(void) searchFieldDidClear:(NSSearchField *) field;
-(void) searchField:(NSSearchField *) field didSearchText:(NSString *) text;

//Inject the 
-(void) rootAccessObject: (id<SSRootAccessProtocol>) object;

@end



