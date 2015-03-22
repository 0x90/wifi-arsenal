//
//  PrefsMap.h
//  KisMAC
//
//  Created by Michael Thole on Mon Jan 20 2003.
//  Copyright (c) 2003 Michael Thole. All rights reserved.
//

#import <AppKit/AppKit.h>

#import "PrefsClient.h"

@interface PrefsMap : PrefsClient
{
    IBOutlet NSColorWell* _cpColor;
    IBOutlet NSColorWell* _traceColor;
    IBOutlet NSColorWell* _wpColor;
    IBOutlet NSColorWell* _areaColorGood;
    IBOutlet NSColorWell* _areaColorBad;
    IBOutlet NSTextField* _areaSens;
    IBOutlet NSTextField* _areaQual;
}

@end
