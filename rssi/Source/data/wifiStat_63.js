var wifiStat1 = [
    {"x": 2.02, "y": 10.98, "room": "FT236", "rssi": [-70, -70, -71, -80, -70, -72, -80, -70, -72, -80, -70, -70, -76, -77, -70, -63, -71, -70, -71, -72], "mean": -72.25, "variance": 17.39},
    {"x": 2.17, "y": 4.98, "room": "FT222", "rssi": [-80, -81, -80, -80, -80, -80, -81, -80, -70, -81, -80, -70, -62, -80, -81, -80, -80, -80, -81, -80], "mean": -78.35, "variance": 23.73},
    {"x": 3.51, "y": 9.02, "room": "hollway_2nd", "rssi": [-45, -72, -72, -72, -72, -72, -72, -73, -72, -72, -74, -72, -72, -72, -72, -73, -72, -73, -72, -72], "mean": -70.9, "variance": 35.59},
    {"x": 5.16, "y": 10.94, "room": "FT235", "rssi": [-62, -62, -62, -63, -49, -64, -63, -62, -62, -63, -62, -63, -62, -63, -63, -62, -62, -65, -62, -62], "mean": -61.9, "variance": 9.39},
    {"x": 5.39, "y": 5.06, "room": "FT223", "rssi": [-78, -78, -78, -78, -78, -76, -76, -78, -76, -76, -78, -78, -77, -78, -78, -77, -78, -78, -76], "mean": -77.37, "variance": 0.76},
    {"x": 8.48, "y": 1.93, "room": "FT223", "rssi": [-83, -84, -83, -83, -83, -83, -83, -83, -83, -83, -84, -83, -84], "mean": -83.23, "variance": 0.18},
    {"x": 9.81, "y": 9.02, "room": "hollway_2nd", "rssi": [-62, -63, -62, -66, -62, -61, -63, -66, -63, -63, -62, -62, -63, -60, -62, -63, -62, -62, -63, -62], "mean": -62.6, "variance": 1.84},
    {"x": 11.57, "y": 5.06, "room": "FT224", "rssi": [-74, -76, -49, -75, -76, -75, -75, -76, -75, -75, -75, -75, -75, -74, -75, -74, -74, -75, -75, -74], "mean": -73.6, "variance": 32.24},
    {"x": 11.57, "y": 1.89, "room": "FT224", "rssi": [-70, -72, -72, -73, -72, -72, -75, -73, -69, -73, -71, -73, -73, -73, -73, -73, -75, -73, -73, -72], "mean": -72.5, "variance": 1.85},
    {"x": 14.48, "y": 10.95, "room": "FT233", "rssi": [-54, -54, -54, -55, -55, -55, -55, -54, -55, -55, -55, -55, -55, -54, -55, -55, -54, -55, -52, -55], "mean": -54.55, "variance": 0.55},
    {"x": 16.12, "y": 9.02, "room": "hollway_2nd", "rssi": [-53, -52, -54, -54, -52, -53, -54, -65, -54, -70, -54, -54, -53, -54, -53, -53, -53, -50, -57, -37], "mean": -53.95, "variance": 35.25},
    {"x": 17.56, "y": 5.06, "room": "FT225", "rssi": [-61, -60, -61, -60, -60, -60, -61, -60, -60, -60, -60, -60, -66, -60, -61, -61, -60, -60, -61, -60], "mean": -60.6, "variance": 1.74},
    {"x": 17.59, "y": 10.95, "room": "FT232", "rssi": [-44, -44, -44, -44, -44, -44, -45, -45, -44, -44, -44, -44, -79, -44, -44, -44, -45, -45, -45, -41], "mean": -45.85, "variance": 58.53},
    {"x": 20.54, "y": 10.94, "room": "FT231", "rssi": [-39, -40, -39, -39, -40, -39, -39, -39, -38, -39, -39, -39, -40, -39, -40, -40, -39, -40, -39, -40], "mean": -39.3, "variance": 0.31},
    {"x": 20.71, "y": 1.65, "room": "FT225", "rssi": [-64, -64, -64, -64, -63, -64, -70, -63, -64, -55, -64, -64, -63, -64, -64, -63, -66, -64, -64, -66], "mean": -63.85, "variance": 6.43},
    {"x": 22.08, "y": 9.02, "room": "hollway_2nd", "rssi": [-51, -53, -53, -53, -53, -53, -52, -53, -53, -52, -52, -53, -53, -53, -53, -53, -51, -52, -53, -52], "mean": -52.55, "variance": 0.45},
    {"x": 23.9, "y": 1.67, "room": "FT226", "rssi": [-68, -69, -69, -68, -69, -69, -69, -69, -74, -69, -71, -72, -69, -69, -72, -67, -69, -71, -69, -68], "mean": -69.5, "variance": 2.65},
    {"x": 26.53, "y": 5.39, "room": "FT226", "rssi": [-75, -74, -78, -75, -74, -78, -75, -72, -78, -74, -76, -73, -74, -74, -74, -73, -74, -74, -74, -78], "mean": -74.85, "variance": 3.13},
    {"x": 26.68, "y": 9.03, "room": "stairs_2nd", "rssi": [-58, -58, -59, -59, -60, -58, -60, -59, -59, -60, -58, -59, -60, -59, -59, -59, -59, -58, -59, -58], "mean": -58.9, "variance": 0.49},
    {"x": 30.28, "y": 1.67, "room": "FT227", "rssi": [-71, -71, -70, -71, -63, -71, -71, -70, -71, -69, -70, -71, -69, -73, -70, -71, -71, -71, -70], "mean": -70.21, "variance": 3.64}
];

var wifiStat2 = [
    {"x": 2.02, "y": 10.98, "room": "FT236", "rssi": [-67, -75, -71, -71, -75, -71, -77, -75, -72, -71, -77, -71, -71, -77, -71, -71, -76, -72, -68, -71], "mean": -72.5, "variance": 8.15},
    {"x": 2.17, "y": 4.98, "room": "FT222", "rssi": [-78, -80, -79, -81, -80, -79, -80, -80, -79, -80, -80, -81, -81, -79, -78, -80, -79, -78, -80, -79], "mean": -79.55, "variance": 0.85},
    {"x": 3.51, "y": 9.02, "room": "hollway_2nd", "rssi": [-73, -70, -70, -73, -68, -68, -73, -68, -72, -68, -73, -73, -67, -73, -69, -73, -71, -74, -73, -71], "mean": -71, "variance": 5},
    {"x": 5.16, "y": 10.94, "room": "FT235", "rssi": [-68, -68, -68, -69, -68, -69, -69, -67, -64, -68, -68, -64, -68, -68, -69, -68, -68, -69, -68, -69], "mean": -67.85, "variance": 1.93},
    {"x": 5.39, "y": 5.06, "room": "FT223", "rssi": [-75, -75, -76, -77, -76, -75, -77, -76, -73, -77, -76, -72, -77, -76, -77, -77, -75, -77, -76], "mean": -75.79, "variance": 1.85},
    {"x": 8.48, "y": 1.93, "room": "FT223", "rssi": [-81, -76, -81, -81, -76, -81, -82, -73, -81, -82, -73, -81, -82, -77, -81, -81, -81, -79, -81, -81], "mean": -79.55, "variance": 7.95},
    {"x": 9.81, "y": 9.02, "room": "hollway_2nd", "rssi": [-62, -63, -66, -63, -63, -62, -63, -62, -62, -63, -62, -62, -62, -63, -62, -63, -63, -62, -47, -63], "mean": -61.9, "variance": 12.49},
    {"x": 11.57, "y": 5.06, "room": "FT224", "rssi": [-75, -75, -75, -75, -75, -76, -75, -75, -76, -76, -75, -76, -76, -75, -76, -74, -75, -76, -75], "mean": -75.32, "variance": 0.32},
    {"x": 11.57, "y": 1.89, "room": "FT224", "rssi": [-61, -71, -69, -71, -71, -70, -71, -70, -70, -71, -76, -70, -70, -71, -62, -70, -71, -71, -70, -71], "mean": -69.85, "variance": 9.53},
    {"x": 14.48, "y": 10.95, "room": "FT233", "rssi": [-51, -51, -51, -51, -51, -49, -51, -52, -51, -51, -51, -50, -51, -51, -50, -51, -51, -51, -51, -51], "mean": -50.85, "variance": 0.33},
    {"x": 16.12, "y": 9.02, "room": "hollway_2nd", "rssi": [-57, -52, -57, -53, -53, -52, -54, -53, -52, -53, -54, -53, -53, -53, -54, -53, -53, -53, -54, -53], "mean": -53.45, "variance": 1.75},
    {"x": 17.56, "y": 5.06, "room": "FT225", "rssi": [-59, -58, -59, -49, -58, -59, -59, -59, -58, -51, -59, -59, -59, -50, -58, -59, -59, -58, -59, -57], "mean": -57.3, "variance": 9.81},
    {"x": 17.59, "y": 10.95, "room": "FT232", "rssi": [-48, -48, -48, -49, -48, -49, -49, -47, -48, -49, -51, -48, -76, -49, -48, -49, -48, -48, -48, -49], "mean": -49.85, "variance": 36.63},
    {"x": 20.54, "y": 10.94, "room": "FT231", "rssi": [-39, -38, -39, -39, -39, -39, -39, -39, -39, -38, -38, -38, -38, -39, -38, -39, -39, -38, -38, -39], "mean": -38.6, "variance": 0.24},
    {"x": 20.71, "y": 1.65, "room": "FT225", "rssi": [-64, -62, -63, -63, -54, -63, -63, -62, -64, -63, -62, -63, -63, -63, -63, -64, -62, -63, -63, -62], "mean": -62.45, "variance": 4.15},
    {"x": 22.08, "y": 9.02, "room": "hollway_2nd", "rssi": [-46, -46, -46, -46, -45, -46, -47, -46, -46, -46, -46, -46, -46, -46, -46, -46, -46, -46, -46, -46], "mean": -46, "variance": 0.1},
    {"x": 23.9, "y": 1.67, "room": "FT226", "rssi": [-74, -72, -72, -75, -74, -73, -73, -74, -72, -73, -74, -73, -72, -75, -74, -72, -75, -74, -72, -73], "mean": -73.3, "variance": 1.11},
    {"x": 26.53, "y": 5.39, "room": "FT226", "rssi": [-75, -76, -77, -75, -76, -77, -50, -75, -76, -75, -76, -76, -76, -76, -76, -76, -71, -75, -76, -71], "mean": -74.05, "variance": 32.85},
    {"x": 26.68, "y": 9.03, "room": "stairs_2nd", "rssi": [-59, -59, -58, -58, -58, -58, -58, -58, -58, -58, -58, -57, -58, -58, -57, -58, -57, -59, -58, -57], "mean": -57.95, "variance": 0.35},
    {"x": 30.28, "y": 1.67, "room": "FT227", "rssi": [-65, -69, -70, -69, -69, -69, -69, -69, -69, -69, -69, -69, -69, -69, -70, -70, -69, -70, -70, -69], "mean": -69.05, "variance": 1.05}
];

var wifiStat = [];

function getWifiStatRepeatability() {
    console.log('Wifi_63')

    $.each(wifiStat1, function (key, val) {
        wifiStat.push({
            'x': val.x,
            'y': val.y,
            'small01_variance': val.variance,
            'small01_mean': val.mean,
            'rssi': val.rssi,
            'room' : val.room
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
        }else {
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
    })

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
        '<td><div class="groupVariance">'  + wifiStat[20].small_mean_variance + '</div></td>' +
        '</tr>';
    $('#wifiTab').append(template)

}
