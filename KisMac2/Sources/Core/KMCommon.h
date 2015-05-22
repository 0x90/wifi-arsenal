/*
 *  KMCommon.h
 *  KisMAC
 *
 *  Created by pr0gg3d on 1/1/09.
 *  Copyright 2009 __MyCompanyName__. All rights reserved.
 *
 */

#import <Foundation/Foundation.h>

enum {
    KMRate1     = 0,
    KMRate2     = 1,
    KMRate5_5   = 2,
    KMRate11    = 3,
    KMRate6     = 4,
    KMRate9     = 5,
    KMRate12    = 6,
    KMRate18    = 7,
    KMRate24    = 8,
    KMRate36    = 9,
    KMRate48    = 10,
    KMRate54    = 11,
};

typedef UInt8 KMRate;

@interface KMCommon : NSObject {
    
}

@end
