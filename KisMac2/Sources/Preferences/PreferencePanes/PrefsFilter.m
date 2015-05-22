//
//  PrefsFilter.m
//  KisMAC
//
//  Created by mick on Tue Sep 16 2003.
//  Copyright (c) 2003 __MyCompanyName__. All rights reserved.
//

#import "PrefsFilter.h"
#import "KisMACNotifications.h"
#import "PrefsController.h"
#import "WaveHelper.h"

@implementation PrefsFilter

-(NSString*)makeValidMACAddress:(NSString*)challenge {
    const char *c;
    int tmp[6];
    NSString *mac = [[challenge stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] uppercaseString];
    //NSString *response;
    
    if ([mac length]<11) return nil;
    if ([mac length]>17) return nil;
        
    c = [mac UTF8String];
    if (sscanf(c,"%2X:%2X:%2X:%2X:%2X:%2X", &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5]) != 6) return nil;
    
    //response = [NSString stringWithFormat:@"%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5]];
    
    //if (![response isEqualToString:mac]) return nil;
    
    return [NSString stringWithFormat:@"%.2X%.2X%.2X%.2X%.2X%.2X", tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5]]; 
}

-(NSString*)makeMAC:(NSString*)mac {
    const char *c;
    int tmp[6];

    c = [mac UTF8String];
    if (sscanf(c,"%2X%2X%2X%2X%2X%2X", &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5]) != 6) return @"invalid MAC";
    
    return [NSString stringWithFormat:@"%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5]];
}

-(void)updateUI {
}

-(IBAction)setValueForSender:(id)sender {
    if(sender == _newItem) {

    } else {
        DBNSLog(@"Error: Invalid sender(%@) in setValueForSender:",sender);
    }
}

- (IBAction)addItem:(id)sender {
    NSString *mac;
    
    NSMutableArray *temp = [NSMutableArray arrayWithArray:[controller objectForKey:@"FilterBSSIDList"]];
    
    mac = [self makeValidMACAddress:[_newItem stringValue]];
    
    if (!mac) {
        NSRunAlertPanel(NSLocalizedString(@"Invalid MAC Address", "for Filter PrefPane"),
            NSLocalizedString(@"Invalid MAC Address description", "LONG description how a MAC looks like"),
            //@"You specified an illegal MAC address. MAC addresses consist of 6 hexvalues seperated by colons.",
            OK, nil, nil);
        return;
    }
    
    if ([temp indexOfObject:mac]!=NSNotFound) {
        NSRunAlertPanel(NSLocalizedString(@"MAC Address exsist", "for Filter PrefPane"), 
            NSLocalizedString(@"MAC Address exsist description", "LONG description"),
            //@"You specified a MAC address, which already exists in the list."
            OK, nil, nil);
        return;
    }
    [temp addObject:mac];
    [controller setObject:temp forKey:@"FilterBSSIDList"];
    [_bssidTable reloadData];
    
    [[NSNotificationCenter defaultCenter] postNotificationName:KisMACFiltersChanged object:self];
}

- (IBAction)removeItem:(id)sender {
    int i;
    NSMutableArray *temp = [NSMutableArray arrayWithArray:[controller objectForKey:@"FilterBSSIDList"]];
    
    for (i=[_bssidTable numberOfRows]; i>=0;i--)
        if ([_bssidTable isRowSelected:i]) {
            [temp removeObjectAtIndex:i];
        }
    [controller setObject:temp forKey:@"FilterBSSIDList"];
    [_bssidTable reloadData];
    [[NSNotificationCenter defaultCenter] postNotificationName:KisMACFiltersChanged object:self];
}

- (id) tableView:(NSTableView *) aTableView
objectValueForTableColumn:(NSTableColumn *) aTableColumn
             row:(int) rowIndex {     
    return [self makeMAC:[controller objectForKey:@"FilterBSSIDList"][rowIndex]]; 
}

- (int)numberOfRowsInTableView:(NSTableView *)aTableView {
   return [[controller objectForKey:@"FilterBSSIDList"] count];
}

- (BOOL)tableView:(NSTableView *)aTableView shouldEditTableColumn:(NSTableColumn *)aTableColumn row:(int)rowIndex {
    return YES;
}

-(void)tableView:(NSTableView *)aTableView setObjectValue:(id)anObject forTableColumn:(NSTableColumn *)aTableColumn row:(int)rowIndex {
    NSString *s;
    NSMutableArray *temp = [NSMutableArray arrayWithArray:[controller objectForKey:@"FilterBSSIDList"]];
    
    s = [self makeValidMACAddress:anObject];
    
    if (s) {
        temp[rowIndex] = s;
        [controller setObject:temp forKey:@"FilterBSSIDList"];
    }
    [aTableView reloadData];
    [[NSNotificationCenter defaultCenter] postNotificationName:KisMACFiltersChanged object:self];
}

@end
