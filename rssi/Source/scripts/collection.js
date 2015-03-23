/**
 * Collection deals with the process of retrieving JSON data from backend and processing them according to the requirement
 *
 * @class collection
 */
app.collection = {

	/**
	 It retrieves the list of Databases from backend in Local or Remote Machine based on the selection
	 @method getDatabaseList
	 @param {String} databaseURL The URL of the selected Server in Local or Remote machine
	 **/
	getDatabaseList: function (data) {
		app.view.showLoader();
		app.view.createDatabaseListUi();
		$.getJSON(data, function (results) {
			app.view.hideLoader();
			app.databaseList = results;
			app.metadataUri = results.metadata;
			app.eventBus.publish("databaseList:retrieved")
		})
	},


	/**
	 It retrieves the list of Collections from backend
	 @method getCollectionList
	 @param {String} databaseUri The URI of the selected Database
	 **/
	getCollectionList: function (data) {
		app.view.showLoader();
		app.view.clearCollectionList();
		app.view.createCollectionListUi();
		$.getJSON(data, function (results) {
			app.view.hideLoader();
			app.collectionList = results;

			app.collectionList = [];
			$.each(results, function (key, val) {
				app.collectionList.push({collection: key, uri: val})
			});
			app.collectionList = _.sortBy(app.collectionList, function (val) {
				return val.collection.toLowerCase();
			});
			app.eventBus.publish("collectionList:retrieved")
		})
	},


	/**
	 It retrieves the internal list of the selected Collection from backend
	 @method getSelectedCollectionData
	 @param {String} collectionUri The URI of the selected Collection
	 **/
	getSelectedCollectionData: function (data) {
		$.getJSON(data, function (results) {
			app.selectedCollectionData = results;
			app.metadataId = results[0].metadata_id;
			app.eventBus.publish("selectedCollectionData:retrieved")
		})
	},


	/**
	 It retrieves the complete RawData of the selected Collection from backend
	 @method getRawData
	 @param {Array} selectedCollectionUrls The Internal URLs of the selected Collection
	 **/
	getRawData: function (data) {
		app.rawData = [];
		$.each(data, function (key, val) {
			$.ajax({
				url: val.URI,
				async: false
			}).done(function (results) {
				results = JSON.parse(results);
				results.receiver_location = results.raw_measurement[0].receiver_location;
				app.rawData.push(results);
			});
		});
		app.rawData = _.sortBy(app.rawData, function (res) {
			return res.receiver_location.coordinate_x;
		});
		app.eventBus.publish("rawData:retrieved")
	},


	/**
	 It filters the RawData based on the selected Floor Plan
	 @method filterRawDataByFloor
	 @param {Array} rawData The rawData of the selected Collection
	 **/
	filterRawDataByFloor: function (data) {
		var zAxis;
		app.filteredRawDataByFloor = [];
		switch (app.selectedFloorPlan) {
			case 'twist2Floor':
				zAxis = 9.53;
				break;
			case 'twist3Floor':
				zAxis = 12.37;
				break;
			case 'twist4Floor':
				zAxis = 16.05;
				break;
			case 'iLab1':
				zAxis = 3;
				break;
			case 'iLab2':
				zAxis = 0;
				break;
		}
		$.each(data, function (key, val) {
			if (val.receiver_location.coordinate_z == zAxis) {
				app.filteredRawDataByFloor.push(val)
			}
		})
	},


	/**
	 It gets the data of the selected Node in the FloorPlan
	 @method getSelectedNodeData
	 @param {String} selectedNodeId The Id of the selected Node in the FloorPlan
	 **/
	getSelectedNodeData: function (data) {
		$.each(app.rawData, function (key, val) {
			if (val.data_id == data) {
				app.selectedNodeData = val
			}
		})
	},


	/**
	 It groups the data of the selected Node based on Channel Number and sorted ascending
	 @method groupNodeDataByChannel
	 @param {Array} selectedNodeData The Data of the selected Node in the FloorPlan
	 **/
	groupNodeDataByChannel: function (data) {
		if ('channel' in data.raw_measurement[0]) {
			var nodeDataGroupedByChannel = _.groupBy(data.raw_measurement, function (val) {
				return val.channel
			});

			app.groupedNodeDataByChannel = [];
			app.channelList = [];

			$.each(nodeDataGroupedByChannel, function (key, val) {
				app.channelList.push(key);
				app.groupedNodeDataByChannel.push({channel: key, data: val})
			});
			app.channelList = _.sortBy(app.channelList)

		} else {
			app.groupedNodeDataByChannel = [];
			app.channelList = ['unknown'];
			app.groupedNodeDataByChannel.push({channel: 'unknown', data: data.raw_measurement})
		}
	},


	/**
	 It gets the data of the selected Channel
	 @method getSelectedChannelData
	 @param {String} selectedChannel The Number of the selected Channel
	 **/
	getSelectedChannelData: function (data) {
		$.each(app.groupedNodeDataByChannel, function (key, val) {
			if (val.channel == data) {
				app.selectedChannelData = val
			}
		})
	},


	/**
	 It groups the data of the selected Channel based on SSID_BSSID and then sorted alphabetically
	 @method groupSelectedChannelDataBySsid
	 @param {Array} selectedChannelData The Data of  of the selected Channel
	 **/
	groupSelectedChannelDataBySsid: function (data) {
		var rssiDataGrouped = _.groupBy(data.data, function (val) {
			return val.sender_id + '_' + val.sender_bssid
		})

		var rssiDataArrayed = [];

		$.each(rssiDataGrouped, function (key, val) {
			rssiDataArrayed.push({ssid: key, data: val})
		})

		app.groupedSsidData = _.sortBy(rssiDataArrayed, function (val) {
			return val.ssid.toLowerCase()
		})
	},

	/**
	 It picks only rssi valued from the data of the selected AccessPoint to feed to the Chart
	 @method processGraphData
	 @param {Array} selectedSsidData The SSID_BSSID Data of the selected AccessPoint
	 **/
	processGraphData: function (data) {
		$.each(app.groupedSsidData, function (key, val) {
			if (val.ssid == data) {
				app.selectedSsidData = val;
				app.graphData = _.map(app.selectedSsidData.data, function (d) {
					return d.rssi
				})
			}
		})
	},


	/**
	 It retrieves the Metadata from backend
	 @method getMetadata
	 @param {String} metadataId The MetadataId of the selected collection
	 **/
	getMetadata: function (data) {
		$.getJSON(app.metadataUri, function (results) {
			var uri = results[app.selectedDatabase.name];
			$.getJSON(uri, function (results) {
				$.each(results, function (key, val) {
					if (val.metadata_id == data) {
						$.getJSON(val.URI, function (results) {
							app.metadata = results;
							app.eventBus.publish("metadata:retrieved")
						})
					}

				})
			})
		})
	}

};

