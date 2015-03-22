/*
        
        File:			WaveStorageController.m
        Program:		KisMAC
		Author:			Michael Rossberg
						mick@binaervarianz.de
		Description:	KisMAC is a wireless stumbler for MacOS X.
                
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
#import "WaveStorageController.h"

#import <BIGeneric/BICompressor.h>
#import <BIGeneric/BIDecompressor.h>

#import "ScanController.h"
#import "WaveHelper.h"
#import "WaveNet.h"
#import "WaveContainer.h"
#import "Trace.h"
#import "ImportController.h"

#ifndef CRCFUNCTION
    #define CRCFUNCTION(s) @"00:00:00:00:00:00:00:00:00:00:00:00:00:00:FF"
#endif

struct pointCoords {
	double x, y;
} __attribute__((packed));

@implementation WaveStorageController

//loads a saved kismac meta file. pre 0.2a
+ (BOOL)loadLegacyFromFile:(NSString*)filename withContainer:(WaveContainer*)container andImportController:(ImportController*)im {
    id data;
    BOOL ret = YES;
	
    NSParameterAssert(filename);
	NSParameterAssert(container);
	NSParameterAssert(im);
    
	NSData *rawData = [NSData dataWithContentsOfFile:filename];
	if (!rawData) {
        DBNSLog(@"Could not load data!");
		return NO;
	}
	
	data = [NSKeyedUnarchiver unarchiveObjectWithData:rawData];
    if (![data isKindOfClass:[NSDictionary class]]) {
        DBNSLog(@"Could not load data, because root object is not a NSDictionary!");
        return NO;
    }
    
    if (data[@"Creator"] && [data[@"Creator"] isEqualToString:@"KisMAC"]) { //could be a new file
        ret &= [[WaveHelper trace] setTrace:data[@"Trace"]];
        ret &= [container loadData:data[@"Networks"]];
    } else {
        ret &= [container loadLegacyData:data]; //try to read legacy data
    }
	
	return ret;
}

//loads a saved kismac meta file
+ (BOOL)loadFromFile:(NSString*)filename withContainer:(WaveContainer*)container andImportController:(ImportController*)im {
	BIDecompressor *deco;
	NSString *creator, *version, *error;
	id data;
	WaveNet *net;
	unsigned int i;
	
    NSParameterAssert(filename);
	NSParameterAssert(container);
	NSParameterAssert(im);
    
	//try to decompress from kismac file. if not successful try with legacy formats
	deco = [[BIDecompressor alloc] initWithFile:filename];
	if (!deco) return [WaveStorageController loadLegacyFromFile:filename 
                                                  withContainer:container andImportController:im];
	
	creator = [deco nextString];
	if (![creator isEqualToString:@"KisMAC"])
    {
		DBNSLog(@"Invaild creator code %@", creator);
		[deco close];
		return NO;
	}
	
	version = [deco nextString];
	DBNSLog(@"Loading KisMAC file created by: %@ %@", creator, version);
	
	data = [NSPropertyListSerialization propertyListFromData:[deco nextData]
                                            mutabilityOption:NSPropertyListImmutable 
                                                      format:nil errorDescription:&error];
	if (!data) 
    {
		DBNSLog(@"Could not decode trace: %@", error);
		[deco close];
		return NO;
	}
	
	[[WaveHelper trace] setTrace:data];
	data = [deco nextData];
	if (!data || [(NSData*)data length] != sizeof(i))
    {
		DBNSLog(@"Could not decode net count");
		[deco close];
		return NO;
	}
	memcpy(&i, [(NSData*)data bytes], sizeof(i));
	
	[im setMax:i];
	while ((data = [deco nextData]) != NULL)
    {
		data = [NSPropertyListSerialization propertyListFromData:data
                                                mutabilityOption:NSPropertyListImmutable 
                                                          format:nil errorDescription:&error];
		if (!data) 
        {
			DBNSLog(@"Could not decode wavenet: %@", error);
			[deco close];
			return NO;
		}
		
		net = [[WaveNet alloc] initWithDataDictionary:data];
		if (net) 
        { //silently discard errors here
			if (![container addNetwork: net])
            {
				DBNSLog(@"Adding a network failed! Make sure you are not hitting MAXNETs");
				[deco close];
				return NO;
			}
		}
		[im increment];
	}
	
	[deco close];
	return YES;
}

//imports the data from a saved file
+ (BOOL)importLegacyFromFile:(NSString*)filename withContainer:(WaveContainer*)container andImportController:(ImportController*)im {
    id data;
    BOOL ret = YES;
    NSDictionary *d;
    
	NSParameterAssert(filename);
	NSParameterAssert(container);
	NSParameterAssert(im);

	data = [NSKeyedUnarchiver unarchiveObjectWithFile:filename];
    if (![data isKindOfClass:[NSDictionary class]]) {
        DBNSLog(@"Could not load data, because root object is not a NSDictionary!");
        return NO;
    }
    
    d = data;
    
    if (d[@"Creator"]) { //could be a new file
        ret &= [[WaveHelper trace] addTrace:d[@"Trace"]];
        ret &= [container importData:d[@"Networks"]];
    } else {
        ret &= [container importLegacyData:d]; //try to read legacy data
    }
	return ret;
}

+ (BOOL)importFromFile:(NSString*)filename withContainer:(WaveContainer*)container andImportController:(ImportController*)im {
	BIDecompressor *deco;
	NSString *creator, *version, *error;
	id data;
	WaveNet *net, *snet;
	unsigned int i, maxID;
	
    NSParameterAssert(filename);
	NSParameterAssert(container);
	NSParameterAssert(im);
    
	//try to decompress from kismac file. if not successful try with legacy formats
	deco = [[BIDecompressor alloc] initWithFile:filename];
	if (!deco) return [WaveStorageController importLegacyFromFile:filename withContainer:container andImportController:im];
	
	creator = [deco nextString];
	if (![creator isEqualToString:@"KisMAC"]) {
		DBNSLog(@"Invaild creator code %@", creator);
		return NO;
	}
	
	version = [deco nextString];
	DBNSLog(@"Loading KisMAC file created by: %@ %@", creator, version);
	
	data = [NSPropertyListSerialization propertyListFromData:[deco nextData] mutabilityOption:NSPropertyListImmutable format:nil errorDescription:&error];
	if (!data) {
		DBNSLog(@"Could not decode trace: %@", error);
		return NO;
	}
	
	[[WaveHelper trace] setTrace:data];
	data = [deco nextData];
	if (!data || [(NSData*)data length] != sizeof(i)) {
		DBNSLog(@"Could not decode net count");
		return NO;
	}
	memcpy(&i, [(NSData*)data bytes], sizeof(i));
	[im setMax:i];
	
	//search for maximum ID. all new nets will be bigger than that
	maxID = 0;
	for (WaveNet *net in container) {
		if ([net netID] > maxID)
			maxID = [net netID];
	}
	
	while ((data = [deco nextData]) != NULL) {
		data = [NSPropertyListSerialization propertyListFromData:data mutabilityOption:NSPropertyListImmutable format:nil errorDescription:&error];
		if (!data) {
			DBNSLog(@"Could not decode wavenet: %@", error);
			return NO;
		}
		
		net = [[WaveNet alloc] initWithDataDictionary:data];
		if (net) { //silently discard errors here
			snet = [container netForKey:[net rawID]];
			if (!snet) {
				if (![container addNetwork:net]) {
					DBNSLog(@"Adding a network failed! Make sure you are not hitting MAXNETs");
					return NO;
				}
				[net setNetID:++maxID];
			} else {
				[snet mergeWithNet:net];
			}
		}
		[im increment];
	}
	
	return YES;
}

#pragma mark -

//imports the data from a netstumbler file
+ (BOOL)importFromNetstumbler:(NSString*)filename withContainer:(WaveContainer*)container andImportController:(ImportController*)im {
    NSMutableArray *a;
    char databuf[1024];
    FILE* fd;
    WaveNet* net;
    unsigned int year, month, day;
    NSString *date;
    	
    NSParameterAssert(filename);
	NSParameterAssert(container);
	NSParameterAssert(im);
    
    a = [NSMutableArray arrayWithCapacity:3000];
    date = @"0000-00-00";
    
    if ((fd = fopen([filename UTF8String], "r")) == NULL) {
        DBNSLog(@"Unable to open specified file: %s", strerror(errno));
        return NO;
    }

    while(!feof(fd)) {
        fgets(databuf, 1023, fd);
        //databuf[strlen(databuf) - 1] = '\0';
        
        if (strncmp(databuf,"NetS",4)) {
            DBNSLog(@"Binary Netstumbler files are not yet supported.");
            return NO;
        }
        
        if (strncmp(databuf, "# $DateGMT: ", 12)==0) {
            if (sscanf(databuf, "# $DateGMT: %d-%d-%d", &year, &day, &month) == 3) {
                date = [NSString stringWithFormat:@"%.4d-%.2d-%.2d", year, day, month];
            }
        }
        if(databuf[0] == '#') continue;
        
        net = [[WaveNet alloc] initWithNetstumbler: databuf andDate:date];
        if (net) {
            [a addObject:net];
        }
    }
    
    fclose(fd);
    [container importData:a];
    
    return YES;
}

//export in wardriving contest format
+ (NSString*)webServiceDataOfContainer:(WaveContainer*)container andImportController:(ImportController*)im  {
    WaveNet *net;
    NSString *type;
    NSString *wep;
    NSString *s, *lat, *lon;
    unsigned int i;
    NSMutableString *output;

	NSParameterAssert(container);
	NSParameterAssert(im);
    
    output = [NSMutableString string];
    
    //this is the header
    [output appendString:@"# $Creator: KisMAC wardriving export version 0.3\n"];
    [output appendString:@"# Latitude\tLongitude\tSSID\tType\tBSSID\tEncryption\tLastSeenDate\tKey\tcrc\n"];
    [output appendString:[[NSDate date] descriptionWithCalendarFormat:@"# $DateGMT: %Y-%m-%d\n" timeZone:[NSTimeZone timeZoneWithAbbreviation:@"GMT"] locale:nil]];
    
    for (i=0; i<[container count]; ++i) {
        net = [container netAtIndex:i];
        
        switch ([net type]) {
            case 1: 
                type = @"IBSS";
                break;
            case 2: 
                type = @"BSS";
                break;
            case 3: 
                type = @"TUNNEL";
                break;
            case 4: 
                type = @"PROBE";
                break;
            case 5: 
                type = @"LTUNNEL";
                break;
            default:
                type = @"NA";
                break;
        }
        switch ([net wep]) {
            case encryptionTypeUnknown: 
                wep = @"NA";
                break;
            case encryptionTypeNone: 
                wep = @"NO";
                break;
            case encryptionTypeWEP:
                wep = @"WEP";
                break;
            case encryptionTypeWEP40: 
                wep = @"WEP-40";
                break;
            case encryptionTypeWPA:
                wep = @"WPA";
                break;
            case encryptionTypeWPA2:
                wep = @"WPA2";
                break;
            case encryptionTypeLEAP: 
                wep = @"LEAP";
                break;
            default:
                wep = @"ERR";
                break;
        }
        
        lat = [net latitude];
        if ([lat length]==0) lat = [NSString stringWithFormat:@"%fN", 0.0f];
        lon = [net longitude];
        if ([lon length]==0) lon = [NSString stringWithFormat:@"%fE", 0.0f];
        
        s = [NSString stringWithFormat:@"%@\t%@\t%@\t%@\t%@\t%@\t%f\t%@", lat, lon, [WaveHelper urlEncodeString:[net SSID]], type, [net BSSID], wep, [[net lastSeenDate] timeIntervalSince1970],[net key]];
        //the CRC function cannot be made public, otherwise everyone can easily upload wrong files...
        if (![net liveCaptured]) [output appendFormat:@"%@\t%@\n", s, @"00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"];
        else [output appendFormat:@"%@\t%@\n", s, CRCFUNCTION(s)];
    }
        
    return output;
}

#pragma mark -

//saves a file
+ (BOOL)saveToFile:(NSString*)filename withContainer:(WaveContainer*)container andImportController:(ImportController*)im {
    NSMutableArray *m;
	BICompressor *c;
	NSString *error = nil;
	NSData *data;
	unsigned int i;
	
    NSParameterAssert(filename);
	NSParameterAssert(container);
	NSParameterAssert(im);
	
	c = [[BICompressor alloc] initWithFile: filename];
	if (!c) return NO;
	
	[c addString:@"KisMAC"];
	[c addString:[[NSBundle mainBundle] infoDictionary][@"CFBundleVersion"]];
    
	m = [[WaveHelper trace] trace];
	if (!m) m = [NSMutableArray array];
	data = [NSPropertyListSerialization dataFromPropertyList:m format:NSPropertyListBinaryFormat_v1_0 errorDescription:&error];
	if (!data)
    {
        [c close];
        return NO;
    }
	if (![c addData:data])
    {
        [c close];
        return NO;
    }
	
	i = [container count];
	if (![c addData:[NSData dataWithBytes:&i length:sizeof(i)]])
    {
        [c close];
        return NO;
    }

	[im setMax:[container count]];
	for (i = 0; i < [container count]; ++i) {
		data = [NSPropertyListSerialization dataFromPropertyList:[[container netAtIndex:i] dataDictionary] format:NSPropertyListBinaryFormat_v1_0 errorDescription:&error];
		if (!data)
        {
            [c close];
            return NO;
        }
		if (![c addData:data])
        {
            [c close];
            return NO;
        }
		
		[im increment];
	}
	
	[c close];
	return YES;
}

//export in netstumbler format
+ (BOOL)exportNSToFile:(NSString*)filename withContainer:(WaveContainer*)container andImportController:(ImportController*)im {
    WaveNet *net;
    float f;
    char c;
    unsigned int i;
    
	NSParameterAssert(filename);
	NSParameterAssert(container);
	NSParameterAssert(im);

    FILE* fd = fopen([filename UTF8String],"w");

    if (!fd) {
        DBNSLog(@"Could not open %@ for writing.", filename);
        return NO;
    }
    
    //this is the header
    fprintf(fd,"# $Creator: KisMAC NS export version 0.2\r\n");
    fprintf(fd,"# $Format: wi-scan with extensions\r\n");
    fprintf(fd,"# Latitude\tLongitude\t( SSID )	Type\t( BSSID )\tTime (GMT)\t[ SNR Sig Noise ]\t# ( Name )\tFlags\tChannelbits\tBcnIntvl\r\n");
    fprintf(fd, "%s", [[[NSDate date] descriptionWithCalendarFormat:@"# $DateGMT: %Y-%m-%d\r\n" timeZone:[NSTimeZone timeZoneWithAbbreviation:@"GMT"] locale:nil] UTF8String]);
    
	[im setMax:[container count]];
    for (i=0; i<[container count]; ++i) {
        net = [container netAtIndex:i];
        
        if (sscanf([[net latitude] UTF8String], "%f%c", &f, &c)==2) fprintf(fd, "%c %f0\t",c,f);
        else fprintf(fd, "N 0.0000000\t");
        
        if (sscanf([[net longitude] UTF8String], "%f%c", &f, &c)==2) fprintf(fd, "%c %f0\t",c,f);
        else fprintf(fd, "E 0.0000000\t");

        fprintf(fd, "( %s )\t", [[net SSID] UTF8String]);
        switch ([net type]) {
            case networkTypeUnknown:
                fprintf(fd,"NA");
                break;
            case networkTypeAdHoc: 
                fprintf(fd,"IBSS");
                break;
            case networkTypeManaged: 
                fprintf(fd,"BSS");
                break;
            case networkTypeTunnel: 
                fprintf(fd,"TUNNEL");
                break;
            case networkTypeProbe: 
                fprintf(fd,"PROBE");
                break;
            case networkTypeLucentTunnel: 
                fprintf(fd,"LTUNNEL");
                break;
            default:
                NSAssert(NO, @"Invalid network type");
        }
        fprintf(fd, "\t( %s )\t", [[net BSSID] UTF8String]);
        fprintf(fd, "%s", [[[net lastSeenDate]
                            descriptionWithCalendarFormat:@"%H:%M:%S (GMT)\t" 
                            timeZone:[NSTimeZone timeZoneWithAbbreviation:@"GMT"] 
                            locale:nil] UTF8String]);
        fprintf(fd, "[ %u %u %u ]\t# ( %s )\t00%s%s\t0000\t0\r\n", [net maxSignal], 
                [net maxSignal], 0, [[net getVendor] UTF8String],[net wep] > encryptionTypeNone ? "1": "0",
                ([net type] == networkTypeAdHoc) ? "2": ([net type] == networkTypeManaged) ? "1" : "0");

		[im increment];
    }
    
    fclose(fd);
    return YES;
}

//export in Google Earth format
+ (BOOL)exportKMLToFile:(NSString*)filename withContainer:(WaveContainer*)container andImportController:(ImportController*)im {
    WaveNet *net;
    float f;
    char c;
    unsigned int i,j;
	double lat,lon=0;
	char netname[80],netesc[80];
    
	NSParameterAssert(filename);
	NSParameterAssert(container);
	NSParameterAssert(im);

    FILE* fd = fopen([filename UTF8String],"w");

    if (!fd) {
        DBNSLog(@"Could not open %@ for writing.", filename);
        return NO;
    }
    
    // KML file header and all styles
	fprintf(fd,"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
	fprintf(fd,"<kml xmlns=\"http://earth.google.com/kml/2.0\">\n");
	fprintf(fd,"<Document>\n");
	fprintf(fd,"	<Style id=\"net_managed_open\">\n");
	fprintf(fd,"		<IconStyle>\n");
	fprintf(fd,"			<Icon>\n");
	fprintf(fd,"				<href>root://icons/palette-4.png</href>\n");
	fprintf(fd,"				<x>128</x>\n");
	fprintf(fd,"				<y>0</y>\n");
	fprintf(fd,"				<w>32</w>\n");
	fprintf(fd,"				<h>32</h>\n");
	fprintf(fd,"			</Icon>\n");
	fprintf(fd,"		</IconStyle>\n");
	fprintf(fd,"	</Style>\n");
	fprintf(fd,"	<Style id=\"net_managed_encrypted\">\n");
	fprintf(fd,"		<IconStyle>\n");
	fprintf(fd,"			<Icon>\n");
	fprintf(fd,"				<href>root://icons/palette-4.png</href>\n");
	fprintf(fd,"				<x>128</x>\n");
	fprintf(fd,"				<y>32</y>\n");
	fprintf(fd,"				<w>32</w>\n");
	fprintf(fd,"				<h>32</h>\n");
	fprintf(fd,"			</Icon>\n");
	fprintf(fd,"		</IconStyle>\n");
	fprintf(fd,"	</Style>\n");
	fprintf(fd,"	<Style id=\"net_adhoc_open\">\n");
	fprintf(fd,"		<IconStyle>\n");
	fprintf(fd,"			<Icon>\n");
	fprintf(fd,"				<href>root://icons/palette-4.png</href>\n");
	fprintf(fd,"				<x>0</x>\n");
	fprintf(fd,"				<y>0</y>\n");
	fprintf(fd,"				<w>32</w>\n");
	fprintf(fd,"				<h>32</h>\n");
	fprintf(fd,"			</Icon>\n");
	fprintf(fd,"		</IconStyle>\n");
	fprintf(fd,"	</Style>\n");
	fprintf(fd,"	<Style id=\"net_adhoc_encrypted\">\n");
	fprintf(fd,"		<IconStyle>\n");
	fprintf(fd,"			<Icon>\n");
	fprintf(fd,"				<href>root://icons/palette-4.png</href>\n");
	fprintf(fd,"				<x>0</x>\n");
	fprintf(fd,"				<y>32</y>\n");
	fprintf(fd,"				<w>32</w>\n");
	fprintf(fd,"				<h>32</h>\n");
	fprintf(fd,"			</Icon>\n");
	fprintf(fd,"		</IconStyle>\n");
	fprintf(fd,"	</Style>\n");
	fprintf(fd,"	<Style id=\"net_tunnel_open\">\n");
	fprintf(fd,"		<IconStyle>\n");
	fprintf(fd,"			<Icon>\n");
	fprintf(fd,"				<href>root://icons/palette-4.png</href>\n");
	fprintf(fd,"				<x>32</x>\n");
	fprintf(fd,"				<y>0</y>\n");
	fprintf(fd,"				<w>32</w>\n");
	fprintf(fd,"				<h>32</h>\n");
	fprintf(fd,"			</Icon>\n");
	fprintf(fd,"		</IconStyle>\n");
	fprintf(fd,"	</Style>\n");
	fprintf(fd,"	<Style id=\"net_tunnel_encrypted\">\n");
	fprintf(fd,"		<IconStyle>\n");
	fprintf(fd,"			<Icon>\n");
	fprintf(fd,"				<href>root://icons/palette-4.png</href>\n");
	fprintf(fd,"				<x>32</x>\n");
	fprintf(fd,"				<y>32</y>\n");
	fprintf(fd,"				<w>32</w>\n");
	fprintf(fd,"				<h>32</h>\n");
	fprintf(fd,"			</Icon>\n");
	fprintf(fd,"		</IconStyle>\n");
	fprintf(fd,"	</Style>\n");
	fprintf(fd,"	<Style id=\"net_probe_open\">\n");
	fprintf(fd,"		<IconStyle>\n");
	fprintf(fd,"			<Icon>\n");
	fprintf(fd,"				<href>root://icons/palette-4.png</href>\n");
	fprintf(fd,"				<x>96</x>\n");
	fprintf(fd,"				<y>0</y>\n");
	fprintf(fd,"				<w>32</w>\n");
	fprintf(fd,"				<h>32</h>\n");
	fprintf(fd,"			</Icon>\n");
	fprintf(fd,"		</IconStyle>\n");
	fprintf(fd,"	</Style>\n");
	fprintf(fd,"	<Style id=\"net_probe_encrypted\">\n");
	fprintf(fd,"		<IconStyle>\n");
	fprintf(fd,"			<Icon>\n");
	fprintf(fd,"				<href>root://icons/palette-4.png</href>\n");
	fprintf(fd,"				<x>96</x>\n");
	fprintf(fd,"				<y>32</y>\n");
	fprintf(fd,"				<w>32</w>\n");
	fprintf(fd,"				<h>32</h>\n");
	fprintf(fd,"			</Icon>\n");
	fprintf(fd,"		</IconStyle>\n");
	fprintf(fd,"	</Style>\n");
	fprintf(fd,"	<Style id=\"net_unknown_open\">\n");
	fprintf(fd,"		<IconStyle>\n");
	fprintf(fd,"			<Icon>\n");
	fprintf(fd,"				<href>root://icons/palette-4.png</href>\n");
	fprintf(fd,"				<x>160</x>\n");
	fprintf(fd,"				<y>0</y>\n");
	fprintf(fd,"				<w>32</w>\n");
	fprintf(fd,"				<h>32</h>\n");
	fprintf(fd,"			</Icon>\n");
	fprintf(fd,"		</IconStyle>\n");
	fprintf(fd,"	</Style>\n");
	fprintf(fd,"	<Style id=\"net_unknown_encrypted\">\n");
	fprintf(fd,"		<IconStyle>\n");
	fprintf(fd,"			<Icon>\n");
	fprintf(fd,"				<href>root://icons/palette-4.png</href>\n");
	fprintf(fd,"				<x>160</x>\n");
	fprintf(fd,"				<y>32</y>\n");
	fprintf(fd,"				<w>32</w>\n");
	fprintf(fd,"				<h>32</h>\n");
	fprintf(fd,"			</Icon>\n");
	fprintf(fd,"		</IconStyle>\n");
	fprintf(fd,"	</Style>\n");
	fprintf(fd,"	<open>1</open>\n");
	fprintf(fd,"\n");

//    fprintf(fd,"# Latitude\tLongitude\t( SSID )	Type\t( BSSID )\tTime (GMT)\t[ SNR Sig Noise ]\t# ( Name )\tFlags\tChannelbits\tBcnIntvl\r\n");

	[im setMax:[container count]];
    for (i=0; i<[container count]; ++i) {
        net = [container netAtIndex:i];
        
		lat = 100;
		
        if (sscanf([[net latitude] UTF8String], "%f%c", &f, &c)==2) lat = f * (c == 'N' ? 1 : -1);		
        if (sscanf([[net longitude] UTF8String], "%f%c", &f, &c)==2) lon = f * (c == 'E' ? 1 : -1);
		strcpy(netname,[[net SSID] cStringUsingEncoding: NSUTF8StringEncoding]);
		
		// now escape any ampersands or < or >...
        // also, ascii chars below ascii value 32 are not valid in xml so skip them
		
		netesc[0]='\0';
		
		for (j=0;j<strlen(netname);++j) {
			switch(netname[j]) {
				case '&':
					strcat(netesc,"&amp;");
					break;
				case '<':
					strcat(netesc,"&lt;");
					break;
				case '>':
					strcat(netesc,"&gt;");
					break;
				default:
                    if (netname[j] < 32) {
                        DBNSLog(@"KML Export: Invalid character found, skipping.");
                    }
                    else {
                         strncat(netesc,netname+j,1);
                    }

			}
		}
		strcpy(netname,netesc);

		if (lat != 100) {
			// we have a valid lat/long pair - skip any that don't
			fprintf(fd,"	<Placemark>\n");
			fprintf(fd,"		<name>%s</name>\n",netname);
			fprintf(fd,"		<description><![CDATA[");
			fprintf(fd,"<b>Signal:</b> %u",[net maxSignal]);
			if (strcmp([[net BSSID] UTF8String],"<no bssid>") != 0) {
				fprintf(fd,"<br><b>BSSID:</b> %s",[[net BSSID] UTF8String]);
				fprintf(fd,"<br><b>Vendor:</b> %s",[[net getVendor] UTF8String]);
			}
			fprintf(fd,"<br><b>Time seen:</b> %s",[[[net lastSeenDate] descriptionWithCalendarFormat:@"%H:%M:%S (GMT)\t" timeZone:[NSTimeZone timeZoneWithAbbreviation:@"GMT"] locale:nil] UTF8String]);
			fprintf(fd,"]]></description>\n");
			fprintf(fd,"		<open>0</open>\n");
			fprintf(fd,"		<styleUrl>#net_");
			switch ([net type]) {
				case networkTypeUnknown:
					fprintf(fd,"unknown");
					break;
				case networkTypeAdHoc: 
					fprintf(fd,"adhoc");
					break;
				case networkTypeManaged: 
					fprintf(fd,"managed");
					break;
				case networkTypeTunnel: 
				case networkTypeLucentTunnel: 
					fprintf(fd,"tunnel");
					break;
				case networkTypeProbe: 
					fprintf(fd,"probe");
					break;
				default:
					NSAssert(NO, @"Invalid network type");
			}
			fprintf(fd,"_%s</styleUrl>\n",[net wep] > encryptionTypeNone ? "encrypted" : "open");
			fprintf(fd,"		<Point>\n");
			fprintf(fd,"			<coordinates>%f,%f</coordinates>\n",lon,lat);
			fprintf(fd,"		</Point>\n");
			fprintf(fd,"	</Placemark>\n");
		}
			
		[im increment];
    }
	fprintf(fd,"\n");

// now export trace (thanks to Jon Steinmetz for Objective-C coding assistance)
	
	NSMutableArray* xtrace = [[WaveHelper trace] trace];
	int traceCount = [xtrace count];
	
	DBNSLog(@"Completed network export - beginning trace export...");

	if (traceCount>0) {
		DBNSLog(@"Traces to export: %d", traceCount);
		fprintf(fd,"    <Style id=\"track\">\n");
		fprintf(fd,"            <LineStyle>\n");
		fprintf(fd,"                    <color>ff00ff33</color>\n");
		fprintf(fd,"                    <width>3</width>\n");
		fprintf(fd,"            </LineStyle>\n");
		fprintf(fd,"    </Style>\n");
		BIValuePair* tempBIValuePair = [[BIValuePair alloc] init];
		int i;
		for (i = 0; i < traceCount; ++i) {
			DBNSLog(@"Trace number: %d", i);
			fprintf(fd,"<Placemark>\n");
			fprintf(fd,"    <name>Trace %d</name>\n",i+1);
			fprintf(fd,"    <styleUrl>#track</styleUrl>\n");
			fprintf(fd,"    <tesselate>1</tesselate>\n");
			fprintf(fd,"    <LineString>\n");
			fprintf(fd,"            <coordinates>\n");
			
			NSMutableData* subtrace = xtrace[i];
			const struct pointCoords *pL = (const struct pointCoords *)[subtrace bytes];
			
			int subtraceCount = [subtrace length] / sizeof(struct pointCoords);
			int j;
			for (j = 0; j < subtraceCount; ++j) {
//				DBNSLog(@"Subtrace: %d", j);
//				DBNSLog(@"pLx, pLy: %f, %f", pL->x, pL->y);
				[tempBIValuePair setPairX: pL->x Y: pL->y];
				waypoint wp = [tempBIValuePair wayPoint];
//				DBNSLog(@"lat, long: %f, %f", wp._lat, wp._long);
				fprintf(fd, "                %f,%f,0\n", wp._long, wp._lat);
				++pL;
			}
			fprintf(fd,"            </coordinates>\n");
			fprintf(fd,"    </LineString>\n");
			fprintf(fd,"</Placemark>\n");
		}
		DBNSLog(@"Completed trace export.");
	} else {
		DBNSLog(@"no trace found - skipping trace export");
	}

	fprintf(fd,"</Document>\n");
	fprintf(fd,"</kml>\n");
    
    fclose(fd);	
    return YES;
}

//export in macstumbler format
+ (BOOL)exportMacStumblerToFile:(NSString*)filename withContainer:(WaveContainer*)container andImportController:(ImportController*)im {
    WaveNet *net;
    NSString *ssid;
    unsigned int i;

	NSParameterAssert(filename);
	NSParameterAssert(container);
	NSParameterAssert(im);

    FILE* fd = fopen([filename UTF8String],"w");
    if (!fd) return NO;
    
	[im setMax:[container count]];
    for (i=0; i < [container count]; i++) {
        net = [container netAtIndex:i];
        ssid = [[net SSID] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if ([ssid isEqualToString:@""]||[ssid isEqualToString:@"<no ssid>"]) ssid=@"(null)";        
        fprintf(fd, "%-34s\t%17s\t%u\t%u\t", [ssid UTF8String], [[net BSSID] UTF8String], [net channel], [net maxSignal]);
        switch ([net type]) {
            case networkTypeUnknown:
                fprintf(fd,"%-10s","Unknown");
                break;
            case networkTypeAdHoc: 
                fprintf(fd,"%-10s","Ad-hoc");
                break;
            case networkTypeManaged: 
                fprintf(fd,"%-10s","Managed");
                break;
            case networkTypeTunnel: 
                fprintf(fd,"%-10s","Tunnel");
                break;
            case networkTypeProbe: 
                fprintf(fd,"%-10s","Probe");
                break;
            case networkTypeLucentTunnel: 
                fprintf(fd,"%-10s","LTunnel");
                break;
        }
        fprintf(fd, "\t%-15s\t", [[net getVendor] UTF8String]);
    
            switch ([net wep]) {
            case encryptionTypeUnknown:
            case encryptionTypeNone: 
                fprintf(fd,"No");
                break;
            case encryptionTypeWEP: 
            case encryptionTypeWEP40:
            case encryptionTypeWPA:
            case encryptionTypeWPA2:
            case encryptionTypeLEAP:
                fprintf(fd,"Yes");
                break;
        }
        
        fprintf(fd, "\t%s\n", [[net comment] UTF8String]);
		[im increment];
    }
    
    fclose(fd);
    return YES;
}

@end
