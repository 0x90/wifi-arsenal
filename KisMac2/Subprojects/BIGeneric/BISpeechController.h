//
//  BISpeechController.h
//  BIGeneric
//
//  Created by mick on Tue Jul 20 2004.
//  Copyright (c) 2004 __MyCompanyName__. All rights reserved.
//

#import <Foundation/Foundation.h>


@interface BISpeechController : NSObject {
    //sound and speech stuff
    long            _selectedVoiceID;
    long            _selectedVoiceCreator;
    SpeechChannel   _curSpeechChannel;
    NSMutableArray* _sentenceQueue;
    BOOL            _speakThread;
    NSLock*         _speakLock;
}

- (void)speakSentence:(CFStringRef)cSentence withVoice:(int)voice;

@end
