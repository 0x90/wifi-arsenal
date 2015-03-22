/*
        
        File:			WaveDriver.m
        Program:		KisMAC
	Author:			Michael Ro§berg
				mick@binaervarianz.de
	Description:		KisMAC is a wireless stumbler for MacOS X.
                
        This file is part of KisMAC.

    KisMAC is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License, version 2,
    as published by the Free Software Foundation;

    KisMAC is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with KisMAC; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#import "WaveDriverAirport.h"
#import "WaveHelper.h"

char WaveDrivers [][30] = {
    "WaveDriverAirport",
    "WaveDriverKismet",
	"WaveDriverKismetDrone",
    "WaveDriverAirportExtreme",
    "WaveDriverUSBIntersil",
    "WaveDriverUSBRalinkRT73",
    "WaveDriverUSBRalinkRT2570",
    "WaveDriverUSBRealtekRTL8187",
    "\0"
};

@implementation WaveDriver

- (id) init {
    self = [super init];
    if (!self)
        return nil;
    
    _permittedRates = nil;
	_currentRate = KMRate11;
    return self;
}
//private
- (unsigned short) getChannelUnCached {
    return 0;
}

#pragma mark -

+ (enum WaveDriverType) type {
    return notSpecifiedDriver;
}

+ (bool) allowsInjection {
    return NO;
}

+ (bool) wantsIPAndPort {
    return NO;
}

+ (bool) allowsChannelHopping {
    return NO;
}

+ (bool) allowsMultipleInstances {
    return NO;
}

+ (NSString*) description {
    return @"meta-driver";
}

+ (NSString*) deviceName {
    return nil;
}

#pragma mark -

+ (bool) loadBackend {
    return NO;
}

+ (bool) unloadBackend {
    return NO;
}

#pragma mark -

- (enum WaveDriverType) type {
    return [[self class] type];
}

- (bool) allowsInjection {
    return [[self class] allowsInjection];
}

- (bool) wantsIPAndPort {
    return [[self class] wantsIPAndPort];
}

- (bool) allowsChannelHopping {
    return [[self class] allowsChannelHopping];
}

- (bool) allowsMultipleInstances {
    return [[self class] allowsMultipleInstances];
}

- (bool) unloadBackend {
    return [[self class] unloadBackend];
}

- (NSString*) deviceName {
    return [[self class] deviceName];
}

#pragma mark -

- (NSComparisonResult)compareDrivers:(WaveDriver *)driver {
    return [[driver deviceName] compare:[self deviceName]];
}

#pragma mark -

- (bool)setConfiguration:(NSDictionary*)dict 
{
    int i, j, supChannelMask;
    NSString *key;
    NSUserDefaults *sets;
    NSMutableArray *a;
    
	_config = dict;
    
    _firstChannel = [_config[@"firstChannel"] intValue];
    if (_firstChannel == 0) _firstChannel = 1;
		_currentChannel = _firstChannel;

    j = 0;
    _fcc = NO;
    _etsi = NO;
    _hopFailure = 0;
    _lastChannel = 0;
    
    supChannelMask = [self allowedChannels];
    for (i = 1; i <= 14; ++i)
    {
        key=[NSString stringWithFormat:@"useChannel%.2i", i];
        if (((supChannelMask >> (i - 1)) & 0x0001) == 0) 
        {
            _useChannel[i - 1] = NO;
        }
        else 
        {
            _useChannel[i - 1] = [_config[key] intValue];
        }
        
        if (_useChannel[i - 1])
        {
            ++j;
        }
        
        if (i == 11 && j == 11) _fcc = YES;
        if (i == 13 && j == 13) _etsi = YES; 
    }
    
    if (j > 1) _hop = YES;
    else _hop = NO;
    
    if (_fcc && (_useChannel[13] | _useChannel[12] | _useChannel[11])) _fcc = NO;
    if (_etsi && _useChannel[13]) _etsi = NO;
    
    _autoAdjustTimer = [_config[@"autoAdjustTimer"] boolValue];
    
    sets = [NSUserDefaults standardUserDefaults];
    a = [[sets objectForKey:@"ActiveDrivers"] mutableCopy];
    for (i = 0; i < [a count]; ++i)
    {
        if ([a[i][@"deviceName"] isEqualToString:[self deviceName]]) 
        {
            a[i] = dict;
        }
    }
    [sets setObject:a forKey:@"ActiveDrivers"];

    return YES;
}

- (NSDictionary*)configuration {
    return _config;
}

- (bool)ETSI {
    return _etsi;
}

- (bool)FCC {
    return _fcc;
}

- (bool)hopping {
    return _hop;
}

- (bool)autoAdjustTimer {
    return _autoAdjustTimer;
}

#pragma mark -

- (unsigned short) getChannel {
    if (![self allowsChannelHopping]) return 0;

    return _currentChannel;
}

- (bool) setChannel:  (unsigned short)newChannel {
    return NO;
}

- (bool) startCapture:(unsigned short)newChannel {
    return YES;
}

- (bool) stopCapture {
    return YES;
}

- (bool) sleepDriver{
    return YES;
}

- (bool) wakeDriver{
    return YES;
}

- (void)hopToNextChannel {
    int channel = _currentChannel+1, i;
   
    if (!_hop) {
        while (_useChannel[channel - 1] == NO) {
            channel = (channel % 14) + 1;
            if (channel == _currentChannel) break; //just make sure it ends
        }
         _currentChannel = [self getChannelUnCached];
         if (_currentChannel == channel) {
             return;
         } else {
             for(i=0; i < 20; ++i) {
                 [self setChannel: channel];
                 _currentChannel = [self getChannelUnCached];
                 if (_currentChannel == channel) break;
             }
             if (i == 20) {
                 [self stopCapture];
                 [self startCapture: channel];
             }
         }
         return;
    }
    
    if (_autoAdjustTimer && (_packets!=0)) {
        if (_autoRepeat<1) {
            ++_autoRepeat;
            return;
        } else _autoRepeat=0;
        _packets = 0;
    }
    
    if (_etsi) channel = ((_currentChannel + 1) % 13) + 1;
    else if (_fcc) channel = ((_currentChannel + 1) % 11) + 1;
    else {
        channel = (_currentChannel % 14) + 1;
        while (_useChannel[channel - 1] == NO) {
            channel = (channel % 14) + 1;
            if (channel == _currentChannel) break; //just make sure it ends
        }
    }
    
    //set the channel and make sure it is set
    //but do not force it too bad
    for(i=0; i < 20; ++i) {
        [self setChannel: channel];
        _currentChannel = [self getChannelUnCached];
        if (channel == _currentChannel) break;
    }
    if (i == 20) {
        [self stopCapture];
        [self startCapture: channel];
    }

    //see if we can switching channel was successful, otherwise the card does may be not support the card
    if (_lastChannel == _currentChannel) {
        ++_hopFailure;
        if (_hopFailure >= 5) {
            _hopFailure = 0;
            DBNSLog(@"Looks like your card does not support channel %d. KisMAC will disable this channel.", channel);
            _useChannel[channel - 1] = NO;
            _etsi = NO;
            _fcc = NO;
        }
    } else {
        _hopFailure = 0;
        _lastChannel = _currentChannel;
    }
}

#pragma mark -

- (NSArray*) networksInRange {
    return nil;
}

- (KFrame*) nextFrame {
    return nil;
}

#pragma mark -

-(bool) startedScanning {
	return YES;
}

-(bool) stoppedScanning {
	return YES;
}

#pragma mark -
#pragma mark Sending frame
#pragma mark

-(bool) sendKFrame:(KFrame *)f howMany:(int)howMany atInterval:(int)interval {
    return NO;
}
-(bool) sendKFrame:(KFrame *)f howMany:(int)howMany atInterval:(int)interval notifyTarget:(id)target notifySelectorString:(NSString *)selector {
    return NO;
}
-(bool) stopSendingFrames {
    return NO;
}

#pragma mark -

- (int) allowedChannels {
    return 0xFFFF;
}

#pragma mark -

- (NSArray *) permittedRates {
    if (!_permittedRates) {
        _permittedRates = @[];
    }
    return _permittedRates;
}
- (KMRate) currentRate {
	return _currentRate;
}
- (bool) setCurrentRate: (KMRate)rate {
	_currentRate = rate;
	return YES;
}

@end
