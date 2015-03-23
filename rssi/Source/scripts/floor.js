/**
 * Floor translates and maps the coordinates of the location information that is included in the RawData.
 * This is achieved based on Offset and Units which are calculated from every Floor Plan image.
 * FloorPlan Image properties are calculated using utils/floor_mapper.html and stored under globals.js
 *
 * @class floor
 */
app.floor = {

	/**
	 It maps the coordinates of location in RawData to the selected Floor Plan
	 @method mapCoordinates
	 @param {Array} rawData The RawData of the selected collection
	 **/
	mapCoordinates: function (data) {
		app.filteredRawDataByFloor = $.each(data, function (key, val) {
			var axis;
			switch (app.selectedFloorPlan) {
				case 'twist2Floor':
					axis = app.floor.pixelConverter(val.receiver_location.coordinate_x, val.receiver_location.coordinate_y,
						app.floorPlanScale.twist2Floor.x_unit, app.floorPlanScale.twist2Floor.y_unit,
						app.floorPlanScale.twist2Floor.left_offset_px,
						(app.floorPlanScale.twist2Floor.top_offset_px + app.floorPlanScale.twist2Floor.height_px ));

					break;

				case 'twist3Floor':
					axis = app.floor.pixelConverter(val.receiver_location.coordinate_x, val.receiver_location.coordinate_y,
						app.floorPlanScale.twist3Floor.x_unit, app.floorPlanScale.twist3Floor.y_unit,
						app.floorPlanScale.twist3Floor.left_offset_px,
						(app.floorPlanScale.twist3Floor.top_offset_px + app.floorPlanScale.twist3Floor.height_px ));
					break;

				case 'twist4Floor':
					axis = app.floor.pixelConverter(val.receiver_location.coordinate_x, val.receiver_location.coordinate_y,
						app.floorPlanScale.twist4Floor.x_unit, app.floorPlanScale.twist4Floor.y_unit,
						app.floorPlanScale.twist4Floor.left_offset_px,
						(app.floorPlanScale.twist4Floor.top_offset_px + app.floorPlanScale.twist4Floor.height_px ));
					break;

				case 'iLab1':
					axis = app.floor.pixelConverter(val.receiver_location.coordinate_x, val.receiver_location.coordinate_y,
						app.floorPlanScale.iLab1.x_unit, app.floorPlanScale.iLab1.y_unit,
						app.floorPlanScale.iLab1.left_offset_px,
						(app.floorPlanScale.iLab1.top_offset_px + app.floorPlanScale.iLab1.height_px ));
					break;

				//iLab2 has (0,0) at top, hence no need to add the height to top_offset

				case 'iLab2':
					axis = app.floor.pixelConverter(val.receiver_location.coordinate_x, val.receiver_location.coordinate_y,
						app.floorPlanScale.iLab2.x_unit, app.floorPlanScale.iLab2.y_unit,
						app.floorPlanScale.iLab2.left_offset_px,
						(app.floorPlanScale.iLab2.top_offset_px));
					break;
			}
			val.receiver_location.coordinate_x_translated = axis[0];
			val.receiver_location.coordinate_y_translated = axis[1];
		});
		app.eventBus.publish("coordinates:mapped")
	},


	/**
	 It translates the original coordinates according to the size of the Floor Plan
	 @method pixelConverter
	 @param {Number} x Original X axis of the location
	 @param {Number} y Original Y axis of the location
	 @param {Number} x_unit One Unit of X Axis of the location in pixels of Floor Plan
	 @param {Number} y_unit One Unit of Y Axis of the location in pixels of Floor Plan
	 @param {Number} left_offset Offset of the Floor Plan Image from left
	 @param {Number} top_offset Offset of the Floor Plan Image from top
	 @return {Object} Translated X and Y axis
	 **/
	pixelConverter: function (x, y, x_unit, y_unit, left_offset, top_offset) {

		var xPix = x * x_unit;
		var yPix = y * y_unit;

		var xAxis = left_offset + xPix;
		var yAxis;

		//iLab2 has (0,0) at top
		if (app.selectedFloorPlan == 'iLab2') {
			yAxis = top_offset + yPix;
		} else {
			yAxis = top_offset - yPix;
		}

		var xAxis = d3.round(xAxis, 2);
		var yAxis = d3.round(yAxis, 2);

		var axis = [xAxis, yAxis];
		return axis;
	}

};




