//
//  TableController.h
//  WirelessConfig
//
//  Created by Zack Smith on 8/17/11.
//  Copyright 2011 wallcity.org All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "Constants.h"

@class ConfigIconCell;

@interface TableController : NSObject {
	//IBOutlet
	IBOutlet NSTableView *tableView;
	
	// NSButtons
	IBOutlet NSPopUpButton *toggleSummaryPredicateButton;


	//NSTableColumns
	IBOutlet NSTableColumn *statusIconCol;
	IBOutlet NSTableColumn *configIconCellCol;
	IBOutlet NSTableColumn *statusTxtCol;
	
	//NSArrays
	NSMutableArray *globalStatusArray;
	
	// Standard ivar Set
	NSBundle *mainBundle;
	NSDictionary *settings;
	BOOL debugEnabled;


	NSMutableArray *aBuffer;

	NSString *statusPredicate;
	
	NSDictionary *lastGlobalStatusUpdate;
	ConfigIconCell *configIconCell;

}
// IBActions
-(IBAction)toggleSummaryPredicate:(id)sender;

// void
- (void)readInSettings ;


// NSTableView
- (void)reloadTableBuffer:(NSDictionary *)globalStatusUpdate;
- (void)reloadTableBufferNow:(NSNotification *) notification;

// NSMutableArray
- (NSMutableArray*)aBuffer;


@end
