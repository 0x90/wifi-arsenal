/**
 * View is responsible for UI manipulation, Templates, UI events handling, etc
 *
 * @class view
 */
app.view = {

	/**
	 It initializes UI by activating JqueryUI components and binds EventHandlers
	 @method initialize
	 **/
	initialize: function () {
		this.bindTitleTabsUi();
		$("#serverList").selectable();
		this.bindServerListUi();
		$("#floorPlanList").selectable();
		this.bindFloorPlanListUi();
		$("#titleTabs").tabs();
		$("#servers").tabs();
		$("#databases").tabs();
		$("#collections").tabs();
		$("#floorPlans").tabs();
		$("#channelMenu").menu();
		$("#accesspoints").tabs();
		$("#floorInfoTabs").tabs();
		$("#graphInfoTabs").tabs();
		$("#accordion").accordion({
			collapsible: true,
			active: 0
		});
	},

	/**
	 It binds EventHandlers with Callback to Tabs in title.
	 @method bindTitleTabsUi
	 **/
	bindTitleTabsUi: function () {
		$("#titleTabs").on("tabsactivate", function (event, ui) {
			if (ui.newTab.context.hash == '#docTab' || ui.newTab.context.hash == '#infoTab'
				|| ui.newTab.context.hash == '#plotTab' || ui.newTab.context.hash == '#statTab') {
				$("#accordion").hide()
			} else {
				$("#accordion").show()
			}
		});
	},

	/**
	 It binds EventHandlers with Callback to the list of servers
	 @method bindServerListUi
	 **/
	bindServerListUi: function () {
		$("#serverList").on("selectableselected", function (event, ui) {
			app.eventBus.publish("server:selected", ui.selected.id)
		});
	},

	/**
	 It binds EventHandlers with Callback to the list of FloorPlans
	 @method bindFloorPlanListUi
	 **/
	bindFloorPlanListUi: function () {
		$("#floorPlanList").on("selectableselected", function (event, ui) {
			app.selectedFloorPlan = ui.selected.id;
			app.eventBus.publish("floorPlan:selected")
		});
	},

	/**
	 It shows the loader when data is being retrieved
	 @method showLoader
	 **/
	showLoader: function () {
		$('#loader').show()
	},

	/**
	 It hides the loader after data is retrieved
	 @method hideLoader
	 **/
	hideLoader: function () {
		$('#loader').hide()
	},

	/**
	 It dynamically creates a database list and activates as JqueryUI Selectable List
	 @method createDatabaseListUi
	 **/
	createDatabaseListUi: function () {
		var template = '<ol id="databaseList" class="selectableList"></ol>';
		$('#database-1').append(template);
		$("#databaseList").selectable();
	},

	/**
	 It clears the database list
	 @method clearDatabaseList
	 **/
	clearDatabaseList: function () {
		$("#database-1").empty()
	},

	/**
	 It adds templates to the list items and add them to the database list and binds EventHandlers with Callback
	 @method updateDatabaseListUi
	 @param {Array} databaseList The list of databases
	 **/
	updateDatabaseListUi: function (data) {
		$.each(data, function (key, val) {
			var template = '<li class="ui-widget-content" href=' + val + '>' + key + '</li>';
			$("#databaseList").append(template)
		})
		$("#databaseList").on("selectableselected", function (event, ui) {
			app.view.resetFloorPlanList();
			app.selectedDatabase = {
				name: $(ui.selected).text(),
				uri: ui.selected.getAttribute('href')
			}
			app.eventBus.publish("database:selected", ui.selected.getAttribute('href'))
		})
	},

	/**
	 It clears the collection list
	 @method clearCollectionList
	 **/
	clearCollectionList: function () {
		$("#collection-1").empty()
	},

	/**
	 It dynamically creates a collection list and activates as JqueryUI Selectable List
	 @method createCollectionListUi
	 **/
	createCollectionListUi: function () {
		var template = '<ol id="collectionList" class="selectableList"></ol>';
		$('#collection-1').append(template);
		$("#collectionList").selectable();
	},

	/**
	 It adds templates to the list items and add them to the collection list and binds EventHandlers with Callback
	 @method updateCollectionListUi
	 @param {Array} collectionList The list of collections
	 **/
	updateCollectionListUi: function (data) {
		$.each(data, function (key, val) {
			var template = '<li class="ui-widget-content" href=' + val.uri + '>' + val.collection + '</li>';
			$('#collectionList').append(template)
		})
		$("#collectionList").on("selectableselected", function (event, ui) {
			app.view.resetFloorPlanList();
			app.selectedCollection = {
				name: $(ui.selected).text(),
				uri: ui.selected.getAttribute('href')
			}
			app.eventBus.publish("collection:selected", ui.selected.getAttribute('href'))
		})
	},

	/**
	 It clears the floor
	 @method clearFloor
	 **/
	clearFloor: function () {
		$("#floor").empty()
	},

	/**
	 It dynamically creates a nodes list and activates as JqueryUI Selectable List
	 @method createNodeList
	 **/
	createNodeList: function () {
		var template = '<ol id="pointsList" class="selectablePoints"></ol>';
		$('#floor').append(template)
		$("#pointsList").selectable();
	},

	/**
	 It shows the floor plan Tab
	 @method showFloorPanel
	 **/
	showFloorPanel: function () {
		$("#accordion").accordion({
			active: 1
		})
	},

	/**
	 It creates the floorPlan container
	 @method createFloorPlan
	 **/
	createFloorPlan: function () {
		$('#floor').removeClass();
		$('#floor').addClass(app.selectedFloorPlan);
	},

	/**
	 It resets the selected node on FloorPlan
	 @method resetFloorPlanList
	 **/
	resetFloorPlanList: function () {
		$('#floorPlanList').find('.ui-selected').removeClass("ui-selected")
	},

	/**
	 It adds templates to the list items and add them to the nodes list and binds EventHandlers with Callback
	 @method updateNodeUi
	 @param {Array} filteredRawDataByFloor The RawData of the selected FloorPlan
	 **/
	updateNodeUi: function (data) {
		app.view.createFloorPlan();
		app.view.clearFloor();
		app.view.clearChannelMenu();
		app.view.clearAccesspointList();
		app.view.createNodeList();

		app.nodeList = [];
		$.each(data, function (key, val) {
			var node = val.receiver_location;
			node.data_id = val.data_id;
			app.nodeList.push(node);

			var template = '<li class="ui-widget-content node" id=node' + val.data_id + '/>';
			$('#pointsList').append(template);

			var nodeId = '#node' + val.data_id;
			$(nodeId).css('left', val.receiver_location.coordinate_x_translated + 'px');
			$(nodeId).css('top', val.receiver_location.coordinate_y_translated + 'px');
		});

		$("#pointsList").on("selectableselected", function (event, ui) {
			app.view.clearAccesspointList();
			var nodeId = ui.selected.id.substr(4);
			app.eventBus.publish("node:selected", nodeId)
		})
	},

	/**
	 It activates the Channel Menu under accesspoints tab
	 @method activateChannelMenu
	 **/
	activateChannelMenu: function () {
		$("#channelMenu").menu("refresh");
		$("#channelMenu").show();
	},

	/**
	 It clears the Channel menu
	 @method clearChannelMenu
	 **/
	clearChannelMenu: function () {
		$("#channelMenu").hide();
		$("#channelList").empty()
	},

	/**
	 It adds templates to the list items and add them to the channels list and binds EventHandlers with Callback
	 @method updateChannelList
	 @param {Array} channelList The list of channel numbers of selected node
	 **/
	updateChannelList: function (data) {
		app.view.clearChannelMenu()

		$.each(data, function (key, val) {
			var template = '<li id=channel' + val + '>' + '<a>' + val + '</a>' + '</li>';
			$('#channelList').append(template)
		})

		app.view.activateChannelMenu();

		$("#channelMenu").on("menuselect", function (event, ui) {
			var channel = ui.item.context.id.substr(7);
			app.eventBus.publish("channel:selected", channel);
		})
	},

	/**
	 It clears the accesspoints list
	 @method clearAccesspointList
	 **/
	clearAccesspointList: function () {
		$("#accesspoint-1").empty()
	},

	/**
	 It dynamically creates a accesspoints list and activates as JqueryUI Selectable List
	 @method createAccesspointListUi
	 **/
	createAccesspointListUi: function () {
		var template = '<ol id="accesspointList" class="selectableList"></ol>';
		$('#accesspoint-1').append(template);
		$("#accesspointList").selectable();
	},

	/**
	 It adds templates to the list items and add them to the accesspoints list and binds EventHandlers with Callback
	 @method updateAccessPointUi
	 @param {Array} groupedSsidData The grouped RSSI data of selected node
	 **/
	updateAccessPointUi: function (data) {
		app.view.clearAccesspointList();
		app.view.createAccesspointListUi();

		$.each(data, function (key, val) {
			var template = '<li class="ui-widget-content" value=' + val.ssid + '>' + val.ssid + '</li>';
			$('#accesspointList').append(template)
		})

		$("#accesspointList").on("selectableselected", function (event, ui) {
			var ssid = ui.selected.getAttribute("value");
			app.eventBus.publish("accessPoint:selected", ssid)
		})

	},

	/**
	 It updates the information related to the selected node of the selected experiment
	 @method updateFloorInfo
	 **/
	updateFloorInfo: function (data) {
		if (_.isEmpty(data)) {
			app.view.updateFloorInfoUi({scan: 0, latency: 0})
		} else {
			if ('latency' in data) {
				app.view.updateFloorInfoUi({scan: data.raw_measurement.length, latency: data.latency})
			} else {
				app.view.updateFloorInfoUi({scan: data.raw_measurement.length, latency: 'Unknown'})
			}
		}

	},

	/**
	 It updates the information related to the selected node of the selected experiment
	 @method updateFloorInfoUi
	 **/
	updateFloorInfoUi: function (data) {
		$('#floorInfoTab-1').empty()
		$('#floorInfoTab-1').append("<b>Number of Measurement Points : </b>" + app.nodeList.length);
		$('#floorInfoTab-1').append("<br>")
		$('#floorInfoTab-1').append("<b>Number of RSSIs measured at the selected Point: </b>" + data.scan);
		$('#floorInfoTab-1').append("<br>")
		$('#floorInfoTab-1').append("<b>Latency measured at the selected Point: </b>" + data.latency);
	},

	/**
	 It shows the graph panel Tab
	 @method showGraphPanel
	 **/
	showGraphPanel: function () {
		$("#accordion").accordion({
			active: 2
		})
	},

	/**
	 It clears the graph panel
	 @method clearGraph
	 **/
	clearGraph: function () {
		$("#graph").empty()
	},

	/**
	 It updates the information related to graph of the selected experiment
	 @method updateGraphInfoUi
	 @param {Object} selectedNodeData.location The Location data of the selected node
	 **/
	updateGraphInfoUi: function (data) {
		var stat = app.utils.statisticsCalculator(app.graphData)
		$('#graphInfoTab-1').empty()
		$('#graphInfoTab-1').append("<br>");
		$('#graphInfoTab-1').append("<b>SSID : </b>" + app.selectedSsidData.data[0].sender_id);
		$('#graphInfoTab-1').append("<br>");
		$('#graphInfoTab-1').append("<b>BSSID : </b>" + app.selectedSsidData.data[0].sender_bssid);
		$('#graphInfoTab-1').append("<br>");
		$('#graphInfoTab-1').append("<b>Total Number of measurements: </b>" + app.selectedSsidData.data.length);
		$('#graphInfoTab-1').append("<br>");
		$('#graphInfoTab-1').append("<br>");
		$('#graphInfoTab-1').append("<b>Data ID : </b>" + data.data_id);
		$('#graphInfoTab-1').append("<br>");
		$('#graphInfoTab-1').append("<b>Room Label : </b>" + data.room_label);
		$('#graphInfoTab-1').append("<br>");
		$('#graphInfoTab-1').append("<b>Coordinate X : </b>" + data.coordinate_x);
		$('#graphInfoTab-1').append("<br>");
		$('#graphInfoTab-1').append("<b>Coordinate Y : </b>" + data.coordinate_y);
		$('#graphInfoTab-1').append("<br>");
		$('#graphInfoTab-1').append("<b>Coordinate Z : </b>" + data.coordinate_z);
		$('#graphInfoTab-1').append("<br>");
		$('#graphInfoTab-1').append("<br>");
		$('#graphInfoTab-1').append("<b> Minimum : </b>" + d3.min(app.graphData));
		$('#graphInfoTab-1').append("<br>");
		$('#graphInfoTab-1').append("<b> Maximum : </b>" + d3.max(app.graphData));
		$('#graphInfoTab-1').append("<br>");
		$('#graphInfoTab-1').append("<b> Mean : </b>" + d3.round(d3.mean(app.graphData), 2));
		$('#graphInfoTab-1').append("<br>");
		$('#graphInfoTab-1').append("<b> Median : </b>" + d3.median(app.graphData));
		$('#graphInfoTab-1').append("<br>");
		$('#graphInfoTab-1').append("<b> Variance : </b>" + d3.round(stat.variance, 2));
		$('#graphInfoTab-1').append("<br>");
		$('#graphInfoTab-1').append("<b> Deviation : </b>" + d3.round(stat.deviation, 2))
	},

	/**
	 It updates the information related to the selected experiment
	 @method updateMetadataUi
	 @param {Object} metadata The metadata of the selected experiment
	 **/
	updateMetadataUi: function (data) {
		$('#description').empty();
		$.each(data.scenario, function (key, val) {
			var heading = '<h3>' + key + '</h3>';
			var text = '<p>' + val + '</p>';
			var template = '<li class="ui-widget-content" >' + heading + text + '</li>';
			$('#description').append(template)
		})
	},

	updatePlotData: function () {
		$('#plotTab').empty();
		var template = 'exp = "' + app.plotData.experiment.substring(12) + '";' + '<br>'
			+ "x = [" + app.plotData.x_axis.join(',') + "];" + '<br>'
			+ "y = [" + app.plotData.y_axis.join(',') + "];" + '<br>'
			+ "z = [" + app.plotData.mean.join(',') + "];" + '<br>'
			+ "variance = [" + app.plotData.variance.join(',') + "];" + '<br>';
		$('#plotTab').append(template);

		var rssi = 1;
		$.each(app.plotData.rssi, function (key, val) {
			template = "rssi" + rssi + " = [" + val.join(',') + "];" + '<br>';
			$('#plotTab').append(template);
			rssi++;
		});

		template = "x = x';" + '<br>' + "y = y';" + '<br>' + "z = z';" + '<br>' + "k = mean(z);" + '<br>' + "k = k*-1;" + '<br>'
		+ "[xx,yy] = meshgrid (linspace (0,30,200));" + '<br>'
		+ "griddata (x,y,z,xx,yy);" + '<br>'
		+ "xlim([0 32]);" + '<br>'
		+ "ylim([0 12]);" + '<br>'
		+ "view([0 90]);" + '<br>'
		+ "title (exp);" + '<br>'
		+ "xlabel('x co-ordinate distance in meters');" + '<br>'
		+ "ylabel('y co-ordinate distance in meters');" + '<br>'
		+ "zlabel('mean of RSSI values in dBm');" + '<br>' + '<br>'
		+ "%clf();" + '<br>'
		+ "%boxplot ({rssi1,rssi2,rssi3,rssi4,rssi5,rssi6,rssi7,rssi8,rssi9,rssi10,rssi11,rssi12,rssi13,rssi14,rssi15,rssi16,rssi17,rssi18,rssi19,rssi20});" + '<br>'
		+ "%hold on" + '<br>'
		+ "%line([0:21], k, 'color', 'green');" + '<br>'
		+ "%hold off" + '<br>'
		+ "%title (exp);" + '<br>'
		+ "%ylabel('RSSI values in dBm');" + '<br>'
		+ "%xlabel('Measurement points');" + '<br>'
		+ "%xlim([0,21]);" + '<br>'
		+ '%set(gca, "XTick", [1:20]);' + '<br>' + '<br>' + '<br>' + '<br>';

		$('#plotTab').append(template);
	},
	updatePlotDataRepeat: function () {
//        $('#plotTab').empty()
		$('#plotTab').append(JSON.stringify(app.plotData.repeat))
	}

}











