//
//  HTTPStream.h
//  KisMAC
//
//  Created by mick on Mon Apr 12 2004.
//  Copyright (c) 2004 __MyCompanyName__. All rights reserved.
//

#import <Foundation/Foundation.h>


@interface HTTPStream : NSObject {
    NSURL *_url;
    NSDictionary *_postVariables;
    bool _inProgress;
    bool _reportErrors;
    int  _errorCode;
    
    CFReadStreamRef _stream;
}

- (id)initWithURL:(NSURL*)url andPostVariables:(NSDictionary*)postVariables reportErrors:(bool)reportErrors;

- (void)setReportErrors:(bool)reportErrors;
- (bool)setURL:(NSURL*) url;
- (bool)setPostVariables:(NSDictionary*)postVariables;
- (bool)execute;
- (bool)working;
- (int)errorCode;
@end
