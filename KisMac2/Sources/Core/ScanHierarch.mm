/*
        
        File:			ScanHierarch.mm
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

#import "ScanHierarch.h"
#import "WaveHelper.h"
#import "WaveNet.h"
#import "WaveContainer.h"

@implementation ScanHierarch
static ScanHierarch *rootItem = nil;	//root item channels
static ScanHierarch *rootItem2 = nil;	//root item ssids
static ScanHierarch *rootItem3 = nil;	//root item ssids

//#define IsALeafNode ((id)-1)
#define IsALeafNode nil

//TODO document this

//creates a new item
- (id)initWithName:(NSString *)name type:(int)newType parent:(ScanHierarch *)obj 
         container:(WaveContainer*)container identkey:(NSString*)idkey 
{
    self = [super init];
    if (!self) return nil;
    
    children = nil;
    aNameString = [name copy];
    aIdentKey = [idkey copy];
    parent = obj;
    _container = container;
    aType = newType;
    
    return self;
}

+ (ScanHierarch *) rootItem:(WaveContainer*)container index:(int)idx
{
    switch (idx)
    {
        case 0:
            if (!rootItem) rootItem = [[ScanHierarch alloc] initWithName:@"Channel" type:1 parent:nil 
                                                               container:container identkey:@""];
            return rootItem;
        case 1:
            if (!rootItem2) rootItem2 = [[ScanHierarch alloc] initWithName:@"SSID" type:2 parent:nil 
                                                                 container:container identkey:@""];
            return rootItem2;
        case 2:
            if (!rootItem3) rootItem3 = [[ScanHierarch alloc] initWithName:@"Encryption" type:36 parent:nil 
                                                                 container:container identkey:@""];
            return rootItem3;
        default:
            return nil;
    }
}

#pragma mark -

- (void) setContainer:(WaveContainer*)container
{
    unsigned int i;
    
	_container = container;
    
    for (i=0;i<[children count];++i)
        [children[i] setContainer:container];
}

+ (void) setContainer:(WaveContainer*)container
{
    [rootItem setContainer:container];
    [rootItem2 setContainer:container];
    [rootItem3 setContainer:container];
}

#pragma mark -


- (void)updateKey 
{
    int *v, h, i;
    unsigned int b, d, u;
    bool found, addedItem;
    int c[14];
    NSString *tmp, *ident;
    NSMutableArray *a;
    WaveNet *n;
    
    addedItem = NO;
    
    if (aType==1) 
    { //channel root item
        for(b=0;b<14;++b) c[b]=0;
        
        for (u=0; u<[_container count]; ++u)
        {
            v=[[_container netAtIndex:u] packetsPerChannel];
            if (v) for(b=0;b<=14;++b) c[b]+=v[b];
        }
        
        for (h=1;h<14;++h)
            if (c[h])
            { 
                //we need this item, check whether it exists
                found = NO;
                for (d=0;d<[children count];++d)
                    if (([(ScanHierarch*)children[d] type]-20)==h) 
                    {
                        found = YES;
                        break;
                    }
                if (!found)
                { 
                    // add a new item
                    tmp=[NSString stringWithFormat:@"%.2i",h];
                    [children addObject:[[ScanHierarch alloc] initWithName:tmp type:20+h parent:self
                                                                 container:_container identkey:@""]];
                    addedItem = YES;
                }
            }
    } 
    else if (aType==2)
    { // SSID root item
        for (u=0; u<[_container count]; ++u)
        {
            tmp=[[_container netAtIndex:u] SSID];
            
            //check whether item exists
            found = NO;
            for (d=0;d<[children count];++d)
            {
                if ([[children[d] nameString] isEqualToString:tmp])
                {
                    found = YES;
                    break;
                }
            }
                
            if (!found)
            {
                // add item
                [children addObject:[[ScanHierarch alloc] initWithName:tmp type:3 parent:self 
                                                             container:_container identkey:@""]];
                addedItem = YES;
            }
        }
        
        // delete all entries which have no BSSIDs below them 
        for (i=[children count]-1;i>=0;i--)
        {
            if ([children[i] numberOfChildren]==0) [children removeObjectAtIndex:i];
        }
    
    }
    else if (aType==3)  // these are the different network SSIDS
    {
        a = [[NSMutableArray alloc] init];
        for (u=0; u<[_container count]; ++u)
        {
            n = [_container netAtIndex:u];
            
            if (![[n SSID] isEqualToString:aNameString]) continue;
            tmp=[n BSSID];
            ident = [n ID];
            
            if (!ident) continue;
            
            [a addObject:ident];
            
            found = NO;
            
            for (d=0;d<[children count];++d)
                if ([[children[d] nameString] isEqualToString:tmp]) 
                {
                    found = YES;
                    break;
                }
                
            if (!found)
            {
                [children addObject:[[ScanHierarch alloc] initWithName:tmp type:99 parent:self container:_container identkey:ident]];
                addedItem = YES;
            }
        }
        
        //remove all items which are not in our list
        for (i=[children count]-1;i>=0;i--) 
        {
            if ([a indexOfObject:[children[i] identKey]] == NSNotFound) 
                    [children removeObjectAtIndex:i];
        }
    } 
    //these are the channel items
    else if ((aType>20)&&(aType<35))
    {
       for (u=0; u<[_container count]; ++u)
       {
            n = [_container netAtIndex:u];
            if (!n) continue;
            
            v = [n packetsPerChannel];
            if (v[aType-20]==0) continue;
            
            tmp = [n BSSID];
            found = NO;
            for (d=0;d<[children count];++d)
            {
                if ([[children[d] nameString] isEqualToString:tmp])
                {
                    found = YES;
                    break;
                }
            }
                
            if (!found)
            {
                [children addObject:[[ScanHierarch alloc] initWithName:tmp type:99 parent:self
                                                             container:_container identkey:[n ID]]];
                addedItem = YES;
             }
        }
    } 
    else if (aType == 36)
    {
        if ([children count]==0)
        {
            //type 39 was reserved for WEP 40
            //these values appear to be encryption type + 36
            [children addObject:[[ScanHierarch alloc] initWithName:@"None" type:37 parent:self container:_container identkey:@"None"]];
            [children addObject:[[ScanHierarch alloc] initWithName:@"WEP"  type:38 parent:self container:_container identkey:@"WEP"]];
            [children addObject:[[ScanHierarch alloc] initWithName:@"WPA"  type:40 parent:self container:_container identkey:@"WPA"]];
            [children addObject:[[ScanHierarch alloc] initWithName:@"LEAP" type:41 parent:self container:_container identkey:@"LEAP"]];
            [children addObject:[[ScanHierarch alloc] initWithName:@"WPA2" type:42 parent:self container:_container identkey:@"WPA2"]];
        }
    }
    
    if (children != IsALeafNode)
		for(d=0;d<[children count];++d)
			[children[d] updateKey];
    if (addedItem)
		[children sortUsingSelector:@selector(compare:)];
    
}

+ (void)updateTree
{
    if (rootItem  != nil) [rootItem updateKey];
    if (rootItem2 != nil) [rootItem2 updateKey];
    if (rootItem3 != nil) [rootItem3 updateKey];
}

- (NSArray *)children 
{
    if (children == NULL) 
    {
        if (aType==1)
        {
            children = [[NSMutableArray alloc] initWithCapacity:13];
            [self updateKey];
        } 
        else if (aType==2)
        {
            children = [[NSMutableArray alloc] init];
            [self updateKey];
        }
        else if (aType==3)
        {
            children = [[NSMutableArray alloc] init];
            [self updateKey];
        }
        else if ((aType>20)&&(aType<35)) 
        {
            children = [[NSMutableArray alloc] init];
            [self updateKey];
        }
        else if (aType==36) 
        {
            children = [[NSMutableArray alloc] initWithCapacity:3];
            [self updateKey];
        }
        else 
        {
            children = IsALeafNode;
        }
    }
    return children;
}

- (NSString *)nameString
{
    return aNameString;
}

- (NSString *)identKey 
{
    return aIdentKey;
}

- (int)type 
{
    return aType;
}

- (ScanHierarch *)childAtIndex:(int)n
{
    return [self children][n];
}

- (int)numberOfChildren 
{
    NSArray * tmp = [self children];
    if (tmp == IsALeafNode)
        return -1;
    else
        return [tmp count];
}

- (NSComparisonResult)compare:(ScanHierarch *)aHier 
{
    return [aNameString compare:[aHier nameString]];
}

- (NSComparisonResult)caseInsensitiveCompare:(ScanHierarch *)aHier
{
    return [aNameString caseInsensitiveCompare:[aHier nameString]];
}

#pragma mark -

- (void)deleteKey
{
    int d;
    if (children != IsALeafNode)
        for (d=[children count]-1;d>=0;d--) 
        {
            [children[d] deleteKey];
            [children removeObjectAtIndex:d];
        }
}

+ (void) clearAllItems
{
    if (rootItem!=nil)
    {
        [rootItem deleteKey];
		rootItem = nil;
    }
    if (rootItem2!=nil)
    { 
        [rootItem2 deleteKey];
		rootItem2 = nil;
    }
    if (rootItem3!=nil) 
    { 
        [rootItem3 deleteKey];
		rootItem3 = nil;
    }
}

- (void)dealloc
{
    children = nil;
}

@end
