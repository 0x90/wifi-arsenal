/**
 * Util contains functions of Javascript functions which are used in APP.
 * There are also other standalone utilities have been used which can be found under /utils/*.html
 *
 * @class utils
 */
app.utils = {
    /**
     It calculates statistics such as mean, variance, deviation of RSSI
     @method statisticsCalculator
     @param {Array} data An Array of RSSI values
     @return {Number, Array} Statistics
     **/
    statisticsCalculator: function (a) {
        var r = {mean: 0, variance: 0, deviation: 0}, t = a.length;
        if(a.length == 0){
            r.deviation = 'No Data'
            r.variance = 'No Data'
            r.deviation = 'No Data'
            return r.deviation,r;
        }else{
            for (var m, s = 0, l = t; l--; s += a[l]);
            for (m = r.mean = s / t, l = t, s = 0; l--; s += Math.pow(a[l] - m, 2));
            return r.deviation = Math.sqrt(r.variance = s / t), r;
        }
    },

    dumpPlotData: function (data) {
        app.plotData.experiment = '';
        app.plotData.x_axis = [];
        app.plotData.y_axis = [];
        app.plotData.mean = [];
        app.plotData.variance = [];
        app.plotData.rssi = [];
        app.plotData.repeat = [];

        $.each(data, function (key, val) {
            app.plotData.experiment = app.selectedCollection.name.replace(/_/g, ' ')
            app.plotData.x_axis.push(val.receiver_location.coordinate_x)
            app.plotData.y_axis.push(val.receiver_location.coordinate_y)

            var rawRSSI = [];
            $.each(val.raw_measurement, function (key, val) {
                if (val.sender_bssid == "64:70:02:3e:9f:63" && val.sender_id == "CREW") {
                    rawRSSI.push(val.rssi)
                }
//                if (val.sender_bssid == "64:70:02:3e:aa:11" && val.sender_ssid == "CREW") {
//                    rawRSSI.push(val.rssi)
//                }
//                if (val.sender_bssid == "64:70:02:3e:aa:d9" && val.sender_ssid == "CREW") {
//                    rawRSSI.push(val.rssi)
//                }
//                if (val.sender_bssid == "64:70:02:3e:aa:ef" && val.sender_ssid == "CREW") {
//                    rawRSSI.push(val.rssi)
//                }
            });
            app.plotData.rssi.push(rawRSSI)

            var stat = app.utils.statisticsCalculator(rawRSSI);
            app.plotData.mean.push(d3.round(stat.mean, 2))
            app.plotData.variance.push(d3.round(stat.variance, 2))

            var mean = d3.round(stat.mean, 2)
            var variance = d3.round(stat.variance, 2)

            app.plotData.repeat.push({
                'x': val.receiver_location.coordinate_x,
                'y': val.receiver_location.coordinate_y,
                'room': val.receiver_location.room_label,
                'rssi': rawRSSI,
                'mean': mean,
                'variance': variance
            })

            app.plotData.repeat = _.sortBy(app.plotData.repeat, function (data) {
                return data.x;
            });


            app.eventBus.publish("plot:data:retrieved")
        });


    }
}

