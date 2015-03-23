/**
 * Globals contains properties, constants and variables used in APP.
 * Important data used during the lifecycle of APP are stored under Globals for the purpose having clean global variables and debugging.
 *
 * @class globals
 */
var app = {

    /**
     AmplifyJS global variable is assigned as Eventbus

     @property eventBus
     @type Object
     **/
    eventBus: amplify,

    /**
     URL of the remote server

     @property dataBaseUriRemote
     @type String
     **/
    dataBaseUriRemote: 'http://ec2-54-217-136-137.eu-west-1.compute.amazonaws.com:5000/evarilos/raw_data/v1.0/database',

    /**
     URL of the local server

     @property dataBaseUriLocal
     @type String
     **/
    dataBaseUriLocal: 'http://localhost:5000/evarilos/raw_data/v1.0/database',

    /**
     URL of the metadata collection

     @property metadataUri
     @type String
     **/
    metadataUri: '',

    /**
     metadataId of the selected experiment

     @property metadataId
     @type String
     **/
    metadataId: '',

    /**
     Metadata of the selected experiment

     @property metadata
     @type Object
     **/
    metadata: {},

    /**
     List of databases of selected server

     @property databaseList
     @type Array
     **/
    databaseList: [],

    /**
     Name and URI of the selected database

     @property selectedDatabase
     @type Object
     **/
    selectedDatabase: {},

    /**
     List of collections of the selected database

     @property collectionList
     @type Array
     **/
    collectionList: [],

    /**
     Name and URI of the selected collection

     @property selectedCollection
     @type Object
     **/
    selectedCollection: {},

    /**
     Internal URI List of the selected collection

     @property selectedCollectionData
     @type Array
     **/
    selectedCollectionData: [],

    /**
     RawData of the selected collection which is a list of RawData from all measurement points of the selected experiment

     @property rawData
     @type Array
     **/
    rawData: [],

    /**
     Name of the selected floor plan

     @property selectedFloorPlan
     @type String
     **/
    selectedFloorPlan: {},

    /**
     RawData filtered by FloorPlan. Even though FloorPlan is selected by USER, some Big collections have data of various FloorPlans altogether
     In order to filter such RawData, extra function is implemented and the result stored in this variable

     @property filteredRawDataByFloor
     @type Array
     **/
    filteredRawDataByFloor: {},

    /**
     List of all measurement points of the selected collection. Measurement Points are defined as nodes through out APP

     @property nodeList
     @type Array
     **/
    nodeList: [],

    /**
     Data of the selected node

     @property selectedNodeData
     @type Array
     **/
    selectedNodeData: [],

    /**
     List of Channel Number which are extracted from the selectedNodeData, if available

     @property channelList
     @type Array
     **/
    channelList: [],

    /**
     Data of selected Node grouped by Channel number

     @property groupedNodeDataByChannel
     @type Array
     **/
    groupedNodeDataByChannel: [],

    /**
     Data of selected Channel

     @property selectedChannelData
     @type Object
     **/
    selectedChannelData: [],

    /**
     RSSI Data grouped by SSID_BSSID

     @property groupedSsidData
     @type Array
     **/
    groupedSsidData: [],

    /**
     RSSI Data of the selected SSID_BSSID

     @property selectedSsidData
     @type Object
     **/
    selectedSsidData: [],

    /**
     Extracted RSSI values of the selected SSID_BSSID that will be fed to the graph

     @property graphData
     @type Array
     **/
    graphData: [],

    /**
     Properties of FloorPlans that contains size of the FloorPlan Image and One Unit of X,Y Axis of the location in pixels of Floor Plan,
     Offset of the Floor Plan Image from left and top. These properties are calculated using utils/floor_mapper.html

     @property floorPlanScale
     @type Object
     **/
    floorPlanScale: {
        twist2Floor: {
            width_px: 736.67,  //x_25_units
            height_px: 411,    //y_15_units
            x_unit: 29.47,
            y_unit: 27.45,
            left_offset_px: (20 - 20),     //adjusted due to unknown or incorrect (0,0) origin
            top_offset_px: 23
        },
        twist3Floor: {
            width_px: 733.67,  //x_25_units
            height_px: 416.67, //y_15_units
            x_unit: 29.35,
            y_unit: 27.78,
            left_offset_px: 22,
            top_offset_px: 21
        },
        twist4Floor: {
            width_px: 733.4,   //x_25_units
            height_px: 418.4,  //y_15_units
            x_unit: 29.34,
            y_unit: 27.9,
            left_offset_px: 22,
            top_offset_px: 21
        },
        iLab1: {
            width_px: 948, //x_57.5_units
            height_px: 415, //y_16.8_units
            x_unit: 14,
            y_unit: 25,
            left_offset_px: 15,
            top_offset_px: 20
        },
        iLab2: {
            width_px: 918, //x_52.5_units
            height_px: 387, //y_16.5_units
            x_unit: 17.48,
            y_unit: 23.45,
            left_offset_px: 35,
            top_offset_px: 45
        }
    },

    floorPlanScale_with_old_images: {
        twist2Floor: {
            width_px: 782,
            height_px: 360,
            x_unit: 26.07,
            y_unit: 24,
            left_offset_px: (67 - 15), //adjusted to calibrate
            top_offset_px: 38
        },
        twist3Floor: {
            width_px: 778,
            height_px: 339,
            x_unit: 25.9,
            y_unit: 22.6,
            left_offset_px: 40,
            top_offset_px: 34
        },
        twist4Floor: {
            width_px: 807,
            height_px: 370,
            x_unit: 26.9,
            y_unit: 24.6,
            left_offset_px: 40,
            top_offset_px: 28
        },
        iLab1: {
            width_px: 944,
            height_px: 412,
            x_unit: 17.92,
            y_unit: 23.13,
            left_offset_px: 15,
            top_offset_px: 49
        }
    },

    plotData : {}

}
