/*
        
        File:			MapViewAreaView.m
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

#import "MapViewAreaView.h"
#import "MapViewPrivate.h"
#import "WaveHelper.h"
#import "ImportController.h"
#import "WaveNet.h"
#import "KisMACNotifications.h"

@implementation MapView(AreaView)

- (void)clearAreaNet {
	_mapImage = _orgImage;
	[self setNeedsDisplay:YES];
}

- (double)getPixelPerDegreeNoZoom {
    double val1, val2;
    
    NS_DURING
        val1 = (_point[selWaypoint1].x - _point[selWaypoint2].x) / (_wp[selWaypoint1]._long - _wp[selWaypoint2]._long);
        val2 = (_point[selWaypoint1].y - _point[selWaypoint2].y) / (_wp[selWaypoint1]._lat  - _wp[selWaypoint2]._lat );
    NS_HANDLER
        val1 = 0.0;
        val2 = 0.0;
    NS_ENDHANDLER
    return (val1 + val2) / 2;
} 

- (void)makeCache:(NSArray*)networks {
    double xx, yy, s, a, r, g, b, d, av, sens, maxd;
    int *c, q, t, networkCount, i, x, y;
    double **f;
    NSPoint p;
    NSDictionary *coord;
    NSEnumerator *e;
    BIValuePair *v;
    NSColor *good, *bad, *col;
    double zoom;
    NSSize imgSize;
    ImportController *im;
    WaveNet *network;
    int qual;
    int **cache;
    int height, width;
    @autoreleasepool
	{
        NSRect rec = NSZeroRect;
		NSSize orgSize = NSZeroSize;
        
        NSParameterAssert(networks);
        NSParameterAssert(_mapImage);
        NSParameterAssert([_mapImage size].width > 1 && [_mapImage size].height > 1);
        
        im = [WaveHelper importController];

        networkCount = [networks count];
		
        if (networkCount==0)
		{
			[im terminateWithCode:[im canceled] ? -1 : 0];
			return;
		}
 
        good = [WaveHelper intToColor:[[NSUserDefaults standardUserDefaults] objectForKey:@"NetAreaColorGood"]];
        bad  = [WaveHelper intToColor:[[NSUserDefaults standardUserDefaults] objectForKey:@"NetAreaColorBad"]];
        sens = [[[NSUserDefaults standardUserDefaults] objectForKey:@"NetAreaSensitivity"] intValue];
        qual = (int)(101.0 - sqrt(([[[NSUserDefaults standardUserDefaults] objectForKey:@"NetAreaQuality"] floatValue])*1000.0));
        zoom = [self getPixelPerDegreeNoZoom];
        imgSize = [_mapImage size];
        
        width = (unsigned int)(imgSize.width );
        width = (width - (width % qual)) / qual +1;
        height= (unsigned int)(imgSize.height);
        height= (height- (height% qual)) / qual +1;
        [im setMax:width];
        
        cache = new int* [width];
        for (x=0; x<width; ++x) {
            cache[x] = new int[height];
            for (t=0; t<height; ++t) cache[x][t]=0;
        }
        
        f = new double* [networkCount];
        c = new int [networkCount];
        
        for (t=0;t<networkCount;++t)
		{
            network = networks[t];
            coord = [network coordinates];
            c[t] = [coord count];
            f[t] = new double[c[t]*3];
            q = 0;
            
            e = [coord keyEnumerator];
            while ((v = [e nextObject]) != nil) {
                p = [self pixelForCoordinateNoZoom:[v wayPoint]];
                f[t][q++] = p.x;
                f[t][q++] = p.y;
                f[t][q++] = [coord[v] intValue];
            }
        }
        
		bool needBreakProcess = true;
		
        for (x = 0; x < width; ++x)
		{
            for (y = 0; y < height; ++y)
			{
                maxd = 0;
                xx = x * qual;
                yy = y * qual;
                
                //IDW algorithm with a decline function
                for (t=0; t < networkCount; ++t)
				{
                    s = 0;
                    av = 0;
                    for (q=0; q<c[t]; ++q) {
                        NS_DURING
                            d = sqrt((xx-f[t][3*q])*(xx-f[t][3*q])+(yy-f[t][3*q+1])*(yy-f[t][3*q+1]));
                            a = 1 / (d * d);
                            av += a;
                            s += a * f[t][3 * q + 2] * (1/d) * (1/30000.0) * (zoom) * sqrt(377.0/(4.0 * 3.1415));
                        NS_HANDLER
                        NS_ENDHANDLER
                    }
                    if (av>0) { 
                        s /= av;
                        if (s > maxd) maxd = s;
                    }
                }
                
                if (maxd>0.1) {
                    col = [bad blendedColorWithFraction:(maxd / sens) ofColor:good];
                    i  = (unsigned int)floor([col alphaComponent] * 255.0 * (maxd < 1.1 ? (maxd-0.1) : 1.0)) << 24;
                    i |= (unsigned int)floor([col redComponent]   * 255) << 16;
                    i |= (unsigned int)floor([col greenComponent] * 255) << 8;
                    i |= (unsigned int)floor([col blueComponent]  * 255);
                    cache[x][y] = i;
                }  else cache[x][y] = 0;
            }
            
            [im increment];
            if ([im canceled])
			{
				needBreakProcess = true;
			}
        }
        
		if (!needBreakProcess) {
			orgSize = [_mapImage size];
			rec.size = NSMakeSize(orgSize.width / width, orgSize.height / height);
			
			[_mapImage lockFocus];
			NS_DURING
			for (x = 0; x< width; ++x)
				for (y = 0; y< height; ++y) {
					i = cache[x][y];
					if (i==0) continue;
					
					a =  (i >> 24) & 0xFF;
					r =  (i >> 16) & 0xFF;
					g =  (i >> 8 ) & 0xFF;
					b =  (i      ) & 0xFF;
					
					[[NSColor colorWithCalibratedRed:r/255.0
											   green:g/255.0
												blue:b/255.0
											   alpha:a/255.0] set];
					rec.origin=NSMakePoint(x * rec.size.width, y * rec.size.height);
					[NSBezierPath fillRect:rec];
				}
			NS_HANDLER
			//if an error occurs make this invalid...
			[[NSNotificationCenter defaultCenter] postNotificationName:KisMACAdvNetViewInvalid
																object:self];
			NS_ENDHANDLER
			[_mapImage unlockFocus];
			[self setNeedsDisplay:YES];
		}
        
        for(t = 0 ; t < networkCount ; ++t)
		{
			delete [] f[t];
		}
        delete [] f;
        delete [] c;

        for (x = 0 ; x < width ; ++x)
		{
            delete [] cache[x];
		}
        delete [] cache;

        [im terminateWithCode:[im canceled] ? -1 : 0];
    }
}

- (void)showAreaNet:(WaveNet*)net {
	NSParameterAssert(net);
	_mapImage = [_orgImage copy];
    [NSThread detachNewThreadSelector:@selector(makeCache:)
							 toTarget:self
						   withObject:@[net]];
}

- (void)showAreaNets:(NSArray*)nets {
	NSParameterAssert(nets);
	_mapImage = [_orgImage copy];
    [NSThread detachNewThreadSelector:@selector(makeCache:)
							 toTarget:self
						   withObject:nets];
}

@end
