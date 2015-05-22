//  ====================================================================== 	//
//  BLAuthentication.h														//
//  																		//
//  Last Modified on Tuesday April 24 2001									//
//  Copyright 2001 Ben Lachman												//
//																			//
//	Thanks to Brian R. Hill <http://personalpages.tds.net/~brian_hill/>		//
//  ====================================================================== 	//

#import <Cocoa/Cocoa.h>
#import <Security/Authorization.h>

@interface BLAuthentication : NSObject 
{
	AuthorizationRef authorizationRef; 
}

// returns a shared instance of the class
+ (id) sharedInstance;

- (BOOL)executeCommand:(NSString *)pathToCommand withArgs:(NSArray *)arguments;

@end




