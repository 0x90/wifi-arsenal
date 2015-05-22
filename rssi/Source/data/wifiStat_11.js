var wifiStat1 = [
    {"x": 2.02, "y": 10.98, "room": "FT236", "rssi": [-87, -87, -87, -87, -87, -87, -87, -87, -87, -87, -87, -87, -87, -87, -87, -87, -87, -87, -87, -88], "mean": -87.05, "variance": 0.05},
    {"x": 2.17, "y": 4.98, "room": "FT222", "rssi": [-72, -72, -72, -58, -72, -72, -70, -71, -72, -71, -70, -71, -72, -70, -71, -72, -70, -72, -72, -68], "mean": -70.5, "variance": 9.35},
    {"x": 3.51, "y": 9.02, "room": "hollway_2nd", "rssi": [-79, -74, -82, -79, -74, -80, -80, -81, -80, -80, -81, -80, -80, -81, -79, -80, -79, -79, -82, -79], "mean": -79.45, "variance": 4.15},
    {"x": 5.16, "y": 10.94, "room": "FT235", "rssi": [-78, -78, -78, -78, -78, -78, -78, -78, -79, -78, -78, -79, -78, -78, -79, -78, -78, -79, -78, -78], "mean": -78.2, "variance": 0.16},
    {"x": 5.39, "y": 5.06, "room": "FT223", "rssi": [-65, -67, -68, -65, -66, -68, -65, -66, -68, -65, -69, -68, -66, -65, -69, -69, -65, -65, -69, -68], "mean": -66.8, "variance": 2.56},
    {"x": 8.48, "y": 1.93, "room": "FT223", "rssi": [-70, -70, -71, -69, -71, -70, -69, -70, -70, -72, -70, -71, -71, -70, -70, -70, -70, -70, -73, -70], "mean": -70.35, "variance": 0.83},
    {"x": 9.81, "y": 9.02, "room": "hollway_2nd", "rssi": [-73, -74, -73, -73, -73, -73, -73, -73, -73, -73, -74, -73, -73, -72, -74, -74, -72, -73, -74], "mean": -73.16, "variance": 0.34},
    {"x": 11.57, "y": 5.06, "room": "FT224", "rssi": [-55, -60, -60, -56, -60, -55, -56, -56, -55, -56, -57, -57, -56, -61, -56, -60, -56, -57, -56, -60], "mean": -57.25, "variance": 3.99},
    {"x": 11.57, "y": 1.89, "room": "FT224", "rssi": [-58, -58, -55, -58, -58, -64, -59, -57, -57, -59, -67, -63, -58, -67, -63, -58, -61, -58, -60, -69], "mean": -60.35, "variance": 14.23},
    {"x": 14.48, "y": 10.95, "room": "FT233", "rssi": [-80, -79, -80, -53, -79, -69, -53, -80, -69, -81, -53, -80, -80, -53, -80, -80, -53, -80, -80, -80], "mean": -72.1, "variance": 132.09},
    {"x": 16.12, "y": 9.02, "room": "hollway_2nd", "rssi": [-63, -68, -63, -68, -68, -64, -68, -71, -64, -72, -64, -72, -72, -64, -68, -69, -64, -69, -68, -68], "mean": -67.35, "variance": 9.03},
    {"x": 17.56, "y": 5.06, "room": "FT225", "rssi": [-57, -57, -81, -57, -57, -57, -57, -57, -57, -56, -57, -57, -57, -62, -57, -82, -57, -56, -56, -57], "mean": -59.55, "variance": 54.95},
    {"x": 17.59, "y": 10.95, "room": "FT232", "rssi": [-72, -71, -71, -73, -71, -71, -55, -72, -71, -72, -72, -71, -72, -71, -71, -72, -71, -71, -72, -71], "mean": -70.65, "variance": 13.23},
    {"x": 20.54, "y": 10.94, "room": "FT231", "rssi": [-68, -68, -69, -68, -68, -68, -68, -68, -54, -55, -68, -54, -55, -68, -68, -69, -69, -68, -69, -68], "mean": -65.5, "variance": 30.45},
    {"x": 20.71, "y": 1.65, "room": "FT225", "rssi": [-55, -55, -55, -56, -57, -55, -56, -54, -55, -56, -55, -57, -55, -57, -54, -56, -54, -55, -56, -54], "mean": -55.35, "variance": 0.93},
    {"x": 22.08, "y": 9.02, "room": "hollway_2nd", "rssi": [-50, -64, -64, -65, -63, -64, -65, -69, -63, -65, -64, -64, -68, -63, -47, -63, -64, -63, -63, -65], "mean": -62.8, "variance": 25.36},
    {"x": 23.9, "y": 1.67, "room": "FT226", "rssi": [-45, -47, -46, -45, -45, -47, -45, -45, -45, -48, -45, -45, -44, -46, -45, -46, -46, -46, -45, -45], "mean": -45.55, "variance": 0.85},
    {"x": 26.53, "y": 5.39, "room": "FT226", "rssi": [-45, -43, -44, -45, -43, -44, -44, -73, -45, -43, -44, -45, -44, -43, -44, -44, -44, -43, -44, -44], "mean": -45.4, "variance": 40.54},
    {"x": 26.68, "y": 9.03, "room": "stairs_2nd", "rssi": [-58, -57, -57, -59, -57, -75, -58, -57, -58, -58, -57, -58, -58, -58, -57, -58, -56, -57, -58, -58], "mean": -58.45, "variance": 14.85},
    {"x": 30.28, "y": 1.67, "room": "FT227", "rssi": [-32, -32, -31, -31, -32, -31, -32, -31, -32, -32, -31, -31, -31, -31, -31, -32, -31, -31, -31, -31], "mean": -31.35, "variance": 0.23}
];

var wifiStat2 = [
    {"x": 2.02, "y": 10.98, "room": "FT236", "rssi": [-85, -87, -87, -83, -85, -87, -87, -85, -87, -87, -73, -87, -87, -73, -85, -87, -83, -85, -87, -83], "mean": -84.5, "variance": 16.75},
    {"x": 2.17, "y": 4.98, "room": "FT222", "rssi": [-80, -76, -80, -80, -76, -78, -80, -76, -78, -80, -76, -78, -80, -78, -80, -78, -80], "mean": -78.47, "variance": 2.6},
    {"x": 3.51, "y": 9.02, "room": "hollway_2nd", "rssi": [-79, -78, -78, -79, -78, -78, -75, -78, -79, -75, -78, -79, -75, -78, -79, -75, -78, -79, -75, -78], "mean": -77.55, "variance": 2.35},
    {"x": 5.16, "y": 10.94, "room": "FT235", "rssi": [-81, -81, -80, -82, -81, -81, -82, -81, -81, -82, -81, -81, -82, -80, -81, -82, -84, -81, -82, -80], "mean": -81.3, "variance": 0.81},
    {"x": 5.39, "y": 5.06, "room": "FT223", "rssi": [-71, -73, -71, -71, -71, -71, -75, -72, -64, -71, -75, -72, -71, -75, -72, -72, -75, -72, -73, -75], "mean": -72.1, "variance": 5.89},
    {"x": 8.48, "y": 1.93, "room": "FT223", "rssi": [-69, -71, -71, -68, -71, -71, -68, -71, -70, -68, -71, -71, -69, -71, -71, -71, -71, -71, -71, -68], "mean": -70.15, "variance": 1.53},
    {"x": 9.81, "y": 9.02, "room": "hollway_2nd", "rssi": [-72, -72, -72, -72, -72, -72, -72, -72, -75, -72, -72, -72, -72, -72, -63, -72, -74, -72, -72, -71], "mean": -71.75, "variance": 4.69},
    {"x": 11.57, "y": 5.06, "room": "FT224", "rssi": [-57, -57, -58, -56, -57, -56, -56, -59, -57, -56, -56, -56, -56, -59, -57, -57, -56, -56, -56, -59], "mean": -56.85, "variance": 1.13},
    {"x": 11.57, "y": 1.89, "room": "FT224", "rssi": [-61, -61, -61, -61, -61, -61, -60, -61, -61, -60, -57, -62, -60, -60, -60, -63, -70, -61, -60, -59], "mean": -61, "variance": 5.6},
    {"x": 14.48, "y": 10.95, "room": "FT233", "rssi": [-84, -83, -81, -82, -82, -81, -82, -84, -81, -82, -83, -81, -84, -82, -67, -84, -82, -67, -83, -82], "mean": -80.85, "variance": 22.33},
    {"x": 16.12, "y": 9.02, "room": "hollway_2nd", "rssi": [-68, -67, -66, -65, -68, -66, -65, -68, -69, -64, -68, -69, -64, -67, -67, -68, -64, -68, -72, -66], "mean": -66.95, "variance": 3.85},
    {"x": 17.56, "y": 5.06, "room": "FT225", "rssi": [-52, -53, -52, -53, -36, -52, -52, -53, -51, -49, -51, -52, -36, -51, -50, -52, -52, -71, -52, -53], "mean": -51.15, "variance": 43.93},
    {"x": 17.59, "y": 10.95, "room": "FT232", "rssi": [-70, -72, -69, -71, -71, -70, -71, -74, -70, -71, -68, -71, -71, -68, -70, -71, -72, -70, -72, -69], "mean": -70.55, "variance": 1.95},
    {"x": 20.54, "y": 10.94, "room": "FT231", "rssi": [-71, -73, -74, -72, -73, -72, -72, -73, -72, -69, -73, -71, -71, -74, -72, -71, -74, -67, -71, -74], "mean": -71.95, "variance": 2.95},
    {"x": 20.71, "y": 1.65, "room": "FT225", "rssi": [-56, -59, -59, -56, -58, -58, -59, -56, -57, -56, -57, -54, -56, -56, -56, -55, -55, -55, -56, -58], "mean": -56.6, "variance": 2.04},
    {"x": 22.08, "y": 9.02, "room": "hollway_2nd", "rssi": [-59, -59, -57, -59, -58, -58, -59, -58, -58, -59, -58, -51, -57, -58, -57, -57, -58, -58, -67, -58], "mean": -58.15, "variance": 6.93},
    {"x": 23.9, "y": 1.67, "room": "FT226", "rssi": [-46, -44, -45, -46, -44, -45, -47, -47, -44, -48, -45, -45, -44, -47, -45, -44, -45, -45, -43, -46], "mean": -45.25, "variance": 1.59},
    {"x": 26.53, "y": 5.39, "room": "FT226", "rssi": [-49, -49, -49, -49, -49, -48, -49, -85, -49, -49, -49, -48, -48, -49, -48, -49, -49, -49, -47, -49], "mean": -50.5, "variance": 62.95},
    {"x": 26.68, "y": 9.03, "room": "stairs_2nd", "rssi": [-53, -53, -53, -53, -56, -52, -53, -52, -57, -52, -79, -53, -53, -79, -53, -38, -53, -53, -52, -53], "mean": -55, "variance": 76.3},
    {"x": 30.28, "y": 1.67, "room": "FT227", "rssi": [-33, -33, -33, -34, -34, -33, -33, -33, -34, -88, -32, -33, -34, -33, -33, -33, -33, -34, -33, -33], "mean": -35.95, "variance": 142.85}
];

var wifiStat = [];

function getWifiStatRepeatability() {
    console.log('Wifi_11')

    $.each(wifiStat1, function (key, val) {
        wifiStat.push({
            'x': val.x,
            'y': val.y,
            'small01_variance': val.variance,
            'small01_mean': val.mean,
            'rssi': val.rssi,
            'room': val.room
        })
    });

    $.each(wifiStat2, function (key, val) {
        wifiStat[key].small02_mean = val.mean;
        wifiStat[key].small02_variance = val.variance;
        wifiStat[key].rssi = wifiStat[key].rssi.concat(val.rssi)
    });

    $.each(wifiStat, function (key, val) {
        if (val.rssi.length != 0) {
            wifiStat[key].groupVariance = d3.round(app.utils.statisticsCalculator(val.rssi).variance, 2)
        } else {
            wifiStat[key].groupVariance = 'No Data'
        }
    })

    wifiStat.push({
        'small01_mean_variance': [],
        'small02_mean_variance': [],

        'small01_avg_mean': [],
        'small02_avg_mean': [],

        'small_mean_variance': []
    })

    $.each(wifiStat, function (key, val) {
            if (key != 20) {

                if (val.small01_variance != 'No Data' && val.small01_mean != 'No Data') {

                    wifiStat[20].small01_mean_variance.push(val.small01_variance);
                    wifiStat[20].small01_avg_mean.push(val.small01_mean);
                }
                if (val.small02_variance != 'No Data' && val.small02_mean != 'No Data') {

                    wifiStat[20].small02_mean_variance.push(val.small02_variance);
                    wifiStat[20].small02_avg_mean.push(val.small02_mean);
                }
                if (val.groupVariance != 'No Data') {

                    wifiStat[20].small_mean_variance.push(val.groupVariance);
                }
            }
        }

    )

    wifiStat[20].small01_mean_variance = d3.round(app.utils.statisticsCalculator(wifiStat[20].small01_mean_variance).mean, 2)
    wifiStat[20].small02_mean_variance = d3.round(app.utils.statisticsCalculator(wifiStat[20].small02_mean_variance).mean, 2)

    wifiStat[20].small01_avg_mean = d3.round(app.utils.statisticsCalculator(wifiStat[20].small01_avg_mean).mean, 2)
    wifiStat[20].small02_avg_mean = d3.round(app.utils.statisticsCalculator(wifiStat[20].small02_avg_mean).mean, 2)

    wifiStat[20].small_mean_variance = d3.round(app.utils.statisticsCalculator(wifiStat[20].small_mean_variance).mean, 2)

    var template = "<tr>" +
        "<td>Measurement Points</td>" +
        "<td>Room</td>" +
        "<td>X in meters</td>" +
        "<td>Y in meters</td>" +
        "<td>Experiment01 Variance</td><td>Experiment01 Mean in dBm</td>" +
        "<td>Experiment02 Variance</td><td>Experiment02 Mean in dBm</td>" +
        "<td>Group Variance</td>" +
        "</tr>";

    $('#wifiTab').append(template)

    var data1m = [];
    var data2m = [];
    var data1v = [];
    var data2v = [];
    var dataGv = [];

    var i = 1;
    $.each(wifiStat, function (key, val) {
        if (key <= 19) {

            data1m.push(val.small01_mean)
            data2m.push(val.small02_mean)
            data1v.push(val.small01_variance)
            data2v.push(val.small02_variance)
            dataGv.push(val.groupVariance)

            template = '<tr>' +
                '<td>' + i + '</td>' +
                '<td>' + val.room + '</td>' +
                '<td>' + val.x + '</td>' +
                '<td>' + val.y + '</td>' +
                '<td>' + val.small01_variance + '</td>' +
                '<td>' + val.small01_mean + '</td>' +
                '<td>' + val.small02_variance + '</td>' +
                '<td>' + val.small02_mean + '</td>' +
                '<td>' + val.groupVariance + '</td>' +
                '</tr>';

            $('#wifiTab').append(template)
            i++;
        }
    });

    console.log("% Wifi_Mean")
    console.log("zWifi_Ex_1_Mean = {" + data1m + "};")
    console.log("zWifi_Ex_2_Mean = {" + data2m + "};")
    console.log("% Wifi_Variance")
    console.log("zWifi_Ex_1_Var = {" + data1v + "};")
    console.log("zWifi_Ex_2_Var = {" + data2v + "};")
    console.log("% Wifi_GVariance")
    console.log("% Wifi_Ex_Group_Var = {" + dataGv + "};")

    template = '<tr>' +
        '<td>' + 'Average' + '</td>' +
        '<td>' + ' ' + '</td>' +
        '<td>' + ' ' + '</td>' +
        '<td>' + ' ' + '</td>' +
        '<td>' + wifiStat[20].small01_mean_variance + '</td>' +
        '<td>' + ' ' + '</td>' +
        '<td>' + wifiStat[20].small02_mean_variance + '</td>' +
        '<td>' + ' ' + '</td>' +
        '<td><div class="groupVariance">' + wifiStat[20].small_mean_variance + '</div></td>' +
        '</tr>';
    $('#wifiTab').append(template)

}
