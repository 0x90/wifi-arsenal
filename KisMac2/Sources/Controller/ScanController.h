/*
        
        File:			ScanController.h
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

#import <Cocoa/Cocoa.h>

typedef enum {
    tabInvalid = -1,
    tabNetworks = 0,
    tabTraffic = 1,
    tabMap = 2,
    tabDetails = 3
} __availableTabs;

@class TrafficController;
@class WaveNet;
@class WaveContainer;
@class BIZoomView;
@class BIToolbarView;
@class MapView;
@class WaveScanner;
@class InfoController;
@class ScanHierarch;
@class ImportController;
@class PrefsController;
@class GrowlController;
@class GPSInfoController;
@class DownloadMapController;

io_connect_t  root_port;    // a reference to the Root Power Domain IOService

//This is the main class. it basically provides an interface between the base and the gui
@interface ScanController : NSObject {
    NSString            *_fileName;             //filename for the currently open capture
    WaveNet             *_curNet;               //the currently selected network
    int                 _selectedRow;
    __availableTabs     _visibleTab;            //which tab visible?
    bool                aNetHierarchVisible;
    bool                aOurDriver;             //did we load the driver?
    bool                _scanning;              //are we scanning?
    bool                _detailsPaneVisibile;   //is the details drawer visible
    bool                _doModal;
    bool                _refreshGUI;
    bool                _saveFilteredOnly;
	bool				_refreshGPS;			// Does GPS need refresh?
    
    NSRect              _zoomToRect;
    
    NSStatusItem        *aStatusItem;
    NSStatusBar         *aStatusBar;
    NSModalSession      aMS;
    NSOpenPanel         *aOP;
    NSString            *_whichDriver;
    int                 _activeDriversCount;
    
    NSString            *_lastSorted;           //name of the last sorted column
    bool                _ascending;             //are we sorting in ascending mode?
    
    ImportController    *_importController;
    int                 _importOpen;
    NSDrawer            *_detailsDrawer;			//the details drawer

    int _crackType;				//weak or bruteforce, just to show the right error message
    SEL _busyFunction;
    bool _asyncFailure;
	NSString *_lastError;
    NSString *_activeAttackNetID;
	NSOperationQueue *queue;
    NSOperationQueue *mainQueue;
    
    IBOutlet WaveContainer      *_container;
    IBOutlet WaveScanner        *scanner;
    IBOutlet NSBox              *_mainView;
    
    IBOutlet NSView             *_networkView;
    IBOutlet NSView             *_trafficView;
    IBOutlet NSView             *_mapView;
    IBOutlet NSView             *_detailsView;
    IBOutlet NSView             *_zoomView;
    IBOutlet BIZoomView         *_slideView;
    IBOutlet BIToolbarView		*_toolBar;
	
    IBOutlet NSTextField        *_headerField;
    IBOutlet NSSearchField      *_searchField;
    IBOutlet NSPopUpButton		*_searchTypeMenu;
    
    IBOutlet MapView            *_mappingView;
    IBOutlet NSWindow           *prefsWindow;
    IBOutlet PrefsController    *prefsController;
    IBOutlet NSView             *detailsView;
    IBOutlet NSToolbarItem      *_scanButton;
    IBOutlet TrafficController  *_trafficController;
    IBOutlet InfoController     *aInfoController;
	IBOutlet GrowlController	*aGrowlController;
	IBOutlet NSTableView        *aDetailsTable;
    IBOutlet NSTableView        *_networkTable;
    IBOutlet NSWindow           *_window;
    IBOutlet NSOutlineView      *aOutView;
    IBOutlet NSMenu             *aNetworkMenu;
    IBOutlet NSMenu             *aCrackMenu;
    IBOutlet NSMenu             *aBruteForceMenu;
    IBOutlet NSMenu             *aChannelMenu;
    IBOutlet NSMenuItem         *_detailsDrawerMenu;
    IBOutlet NSMenuItem         *_debugMenu;
    IBOutlet NSMenuItem         *_deauthMenu;
	IBOutlet NSMenuItem			*_deauthAllMenu;
    IBOutlet NSMenuItem         *_authFloodMenu;
	IBOutlet NSMenuItem			*_monitorMenu;
	IBOutlet NSMenuItem			*_monitorAllMenu;
    IBOutlet NSMenuItem         *aInjPacketsMenu;
    IBOutlet NSMenuItem         *_showNetInMap;
    IBOutlet NSMenuItem         *_showAllNetsInMap;
	IBOutlet NSMenuItem			*_fullscreen;
    
    IBOutlet NSMenuItem         *_showNetworks;
    IBOutlet NSMenuItem         *_showTraffic;
    IBOutlet NSMenuItem         *_showMap;
    IBOutlet NSMenuItem         *_showDetails;
    IBOutlet NSMenuItem         *_showHierarch;
	IBOutlet NSMenuItem			*_showGPSDetails;
    
    IBOutlet NSPopUpButton      *_trafficTimePopUp;
    IBOutlet NSPopUpButton      *_trafficModePopUp;
    IBOutlet NSDrawer           *_netHierarchDrawer;
	GPSInfoController* _g;
	NSWindow *borderlessWindow;
    DownloadMapController* dmc;
}

- (IBAction)updateNetworkTable:(id)sender complete:(BOOL)complete;

- (IBAction)showInfo:(id)sender;
- (IBAction)showNetHierarch:(id)sender;

- (IBAction)changeSearchValue:(id)sender;
- (IBAction)changeSearchType:(id)sender;
- (void)checkFilter:(id)sender;
@end

@interface ScanController(MenuExtension) 
- (IBAction)showPrefs:(id)sender;

- (IBAction)importKismetXML:(id)sender;
- (IBAction)importNetstumbler:(id)sender;
- (IBAction)importMapFromServer:(id)sender;

- (IBAction)exportNS:(id)sender;
- (IBAction)exportKMLFile:(id)sender;
- (IBAction)exportWarD:(id)sender;
- (IBAction)exportMacstumbler:(id)sender;
- (IBAction)exportPDF:(id)sender;
- (IBAction)exportJPEG:(id)sender;

- (IBAction)selChannel:(id)sender;
- (IBAction)selChannelRange:(id)sender;
- (IBAction)setAutoAdjustTimer:(id)sender;

- (IBAction)testInjection:(id)sender;
- (IBAction)clearNetwork:(id)sender;
- (IBAction)joinNetwork:(id)sender;

- (IBAction)deautheticateNetwork:(id)sender;
- (IBAction)deautheticateAllNetworks:(id)sender;
- (IBAction)authFloodNetwork:(id)sender;
- (IBAction)monitorSignal:(id)sender;
- (IBAction)monitorAllNetworks:(id)sender;
- (IBAction)injectPackets:(id)sender;

- (IBAction)restartGPS:(id)sender;
- (IBAction)showCurNetArea:(id)sender;
- (IBAction)showAllNetArea:(id)sender;
- (IBAction)displayGPSInfo:(id)sender;


- (IBAction)closeActiveWindow:(id)sender;

- (IBAction)openWebsiteURL:(id)sender;
- (IBAction)openDonateURL:(id)sender;
- (IBAction)openForumsURL:(id)sender;
- (IBAction)openFAQURL:(id)sender;
- (IBAction)showContextHelp:(id)sender;

- (IBAction)debugSaveStressTest:(id)sender;
- (IBAction)gpsDebugToConsole:(id)sender;
- (IBAction)debugBeaconFlood:(id)sender;
- (IBAction)debugTestWPAHashingFunction:(id)sender;
- (IBAction)debugExportTrafficView:(id)sender;

void NotifySleep( void * refCon, io_service_t service,
                      natural_t messageType, void * messageArgument );
@end
