var wifiStat1 = [
    {"x": 2.02, "y": 10.98, "room": "FT236", "rssi": [-76, -46, -60, -61, -60, -59, -60, -60, -59, -60, -60, -54, -59, -60, -54, -59, -47, -54, -59, -60], "mean": -58.35, "variance": 34.03},
    {"x": 2.17, "y": 4.98, "room": "FT222", "rssi": [-41, -44, -41, -41, -44, -40, -41, -43, -40, -40, -43, -40, -40, -65, -41, -41, -41, -41, -45, -40], "mean": -42.6, "variance": 28.64},
    {"x": 3.51, "y": 9.02, "room": "hollway_2nd", "rssi": [-54, -54, -53, -53, -54, -54, -56, -58, -57, -53, -57, -54, -55, -47, -54, -54, -53, -54, -54, -54], "mean": -54.1, "variance": 4.59},
    {"x": 5.16, "y": 10.94, "room": "FT235", "rssi": [-56, -51, -53, -53, -54, -54, -53, -49, -52, -54, -50, -53, -54, -57, -52, -57, -54, -54, -53, -53], "mean": -53.3, "variance": 3.81},
    {"x": 5.39, "y": 5.06, "room": "FT223", "rssi": [-45, -63, -43, -44, -43, -44, -42, -43, -44, -45, -42, -43, -45, -44, -43, -43, -43, -43, -43, -41], "mean": -44.3, "variance": 19.41},
    {"x": 8.48, "y": 1.93, "room": "FT223", "rssi": [-43, -43, -44, -44, -43, -44, -44, -45, -44, -43, -44, -44, -44, -44, -39, -43, -44, -42, -44, -47], "mean": -43.6, "variance": 2.04},
    {"x": 9.81, "y": 9.02, "room": "hollway_2nd", "rssi": [-73, -54, -54, -73, -53, -54, -54, -59, -54, -57, -57, -53, -54, -54, -54, -53, -53, -54, -54, -54], "mean": -56.25, "variance": 33.39},
    {"x": 11.57, "y": 5.06, "room": "FT224", "rssi": [-55, -55, -54, -55, -55, -55, -54, -54, -55, -54, -53, -55, -56, -54, -55, -57, -54, -53, -49, -55], "mean": -54.35, "variance": 2.33},
    {"x": 11.57, "y": 1.89, "room": "FT224", "rssi": [-48, -47, -48, -48, -47, -51, -49, -47, -49, -50, -48, -48, -49, -48, -48, -49, -48, -48, -44, -49], "mean": -48.15, "variance": 1.83},
    {"x": 14.48, "y": 10.95, "room": "FT233", "rssi": [-75, -70, -75, -68, -70, -70, -68, -70, -70, -75, -69, -70, -75, -70, -69, -72, -75, -75, -72, -75], "mean": -71.65, "variance": 6.93},
    {"x": 16.12, "y": 9.02, "room": "hollway_2nd", "rssi": [-70, -70, -71, -71, -70, -71, -71, -70, -71, -70, -70, -71, -70, -71, -71, -70, -71, -71, -70, -71], "mean": -70.55, "variance": 0.25},
    {"x": 17.56, "y": 5.06, "room": "FT225", "rssi": [-53, -57, -57, -57, -57, -56, -57, -57, -54, -57, -54, -57, -57, -57, -54, -54, -57, -57, -57, -57], "mean": -56.15, "variance": 1.93},
    {"x": 17.59, "y": 10.95, "room": "FT232", "rssi": [-74, -78, -79, -80, -71, -79, -79, -80, -79, -79, -77, -78, -78, -78, -78, -78, -79, -78, -78, -79], "mean": -77.95, "variance": 4.05},
    {"x": 20.54, "y": 10.94, "room": "FT231", "rssi": [-86, -83, -86, -86, -83, -86, -86, -85, -86, -86, -85, -83, -86, -84, -85, -86, -86, -85, -76, -86], "mean": -84.75, "variance": 5.19},
    {"x": 20.71, "y": 1.65, "room": "FT225", "rssi": [-64, -63, -64, -68, -63, -64, -64, -63, -63, -64, -64, -64, -63, -64, -64, -65, -64, -64, -64, -64], "mean": -64, "variance": 1.1},
    {"x": 22.08, "y": 9.02, "room": "hollway_2nd", "rssi": [-77, -77, -77, -76, -76, -77, -76, -76, -77, -76, -77, -77, -76, -76, -77, -77, -76, -76, -77, -76], "mean": -76.5, "variance": 0.25},
    {"x": 23.9, "y": 1.67, "room": "FT226", "rssi": [-72, -69, -71, -71, -68, -72, -67, -68, -71, -67, -68, -71, -71, -90, -63, -70, -90, -72, -53, -69], "mean": -70.65, "variance": 58.93},
    {"x": 26.53, "y": 5.39, "room": "FT226", "rssi": [-63, -62, -64, -63, -53, -63, -63, -63, -64, -63, -62, -62, -63, -63, -62, -63, -63, -63, -63, -63], "mean": -62.4, "variance": 4.94},
    {"x": 26.68, "y": 9.03, "room": "stairs_2nd", "rssi": [-76, -77, -77, -76, -79, -77, -75, -75, -76, -78, -75, -75, -78, -75, -76, -77, -76, -76, -77, -76], "mean": -76.35, "variance": 1.23},
    {"x": 30.28, "y": 1.67, "room": "FT227", "rssi": [-63, -64, -64, -64, -64, -64, -64, -64, -63, -64, -64, -63, -63, -64, -63, -64, -64, -63, -64, -64], "mean": -63.7, "variance": 0.21}
];

var wifiStat2 = [
    {"x": 2.02, "y": 10.98, "room": "FT236", "rssi": [-56, -53, -57, -57, -58, -56, -57, -56, -57, -56, -57, -52, -51, -52, -56, -57, -60, -56, -57, -56], "mean": -55.85, "variance": 4.63},
    {"x": 2.17, "y": 4.98, "room": "FT222", "rssi": [-39, -40, -39, -40, -40, -39, -39, -39, -38, -39, -39, -38, -39, -39, -39, -39, -39, -39, -40, -39], "mean": -39.1, "variance": 0.29},
    {"x": 3.51, "y": 9.02, "room": "hollway_2nd", "rssi": [-49, -53, -49, -70, -49, -49, -49, -52, -49, -43, -44, -60, -49, -44, -49, -53, -48, -49, -51, -49], "mean": -50.4, "variance": 32.74},
    {"x": 5.16, "y": 10.94, "room": "FT235", "rssi": [-55, -54, -54, -55, -54, -49, -54, -54, -55, -55, -54, -55, -55, -55, -55, -54, -54, -55, -55, -54], "mean": -54.25, "variance": 1.69},
    {"x": 5.39, "y": 5.06, "room": "FT223", "rssi": [-46, -47, -47, -46, -46, -45, -45, -46, -46, -46, -46, -45, -46, -45, -46, -46, -46, -47, -47, -47], "mean": -46.05, "variance": 0.45},
    {"x": 8.48, "y": 1.93, "room": "FT223", "rssi": [-49, -50, -49, -49, -49, -48, -50, -49, -49, -49, -49, -49, -49, -49, -49, -49, -48, -49, -49, -49], "mean": -49, "variance": 0.2},
    {"x": 9.81, "y": 9.02, "room": "hollway_2nd", "rssi": [-54, -54, -52, -54, -52, -54, -54, -54, -54, -54, -54, -57, -54, -51, -54, -54, -55, -54, -51, -52], "mean": -53.6, "variance": 1.84},
    {"x": 11.57, "y": 5.06, "room": "FT224", "rssi": [-55, -52, -51, -51, -51, -52, -54, -48, -49, -51, -51, -50, -51, -52, -52, -51, -51, -54, -51, -51], "mean": -51.4, "variance": 2.44},
    {"x": 11.57, "y": 1.89, "room": "FT224", "rssi": [-51, -51, -51, -50, -51, -52, -51, -50, -51, -52, -51, -60, -52, -51, -51, -52, -71, -52, -50, -50], "mean": -52.5, "variance": 22.25},
    {"x": 14.48, "y": 10.95, "room": "FT233", "rssi": [-75, -75, -69, -75, -75, -75, -75, -75, -75, -75, -74, -76, -76, -76, -75, -55, -75, -75, -75], "mean": -73.74, "variance": 21.56},
    {"x": 16.12, "y": 9.02, "room": "hollway_2nd", "rssi": [-70, -70, -69, -70, -70, -69, -70, -70, -70, -70, -70, -67, -74, -50, -70, -70, -69, -70, -70, -70], "mean": -68.9, "variance": 20.19},
    {"x": 17.56, "y": 5.06, "room": "FT225", "rssi": [-61, -60, -61, -61, -61, -61, -61, -60, -61, -63, -60, -61, -60, -61, -61, -60, -61, -61, -48, -64], "mean": -60.35, "variance": 8.93},
    {"x": 17.59, "y": 10.95, "room": "FT232", "rssi": [-74, -75, -76, -74, -75, -75, -75, -76, -75, -75, -76, -75, -75, -75, -75, -75, -75, -78, -75, -75], "mean": -75.2, "variance": 0.66},
    {"x": 20.54, "y": 10.94, "room": "FT231", "rssi": [-82, -83, -83, -82, -83, -83, -82, -83, -83, -82, -75, -77, -83, -82, -82, -83, -82, -82, -83, -83], "mean": -81.9, "variance": 4.19},
    {"x": 20.71, "y": 1.65, "room": "FT225", "rssi": [-64, -64, -64, -61, -64, -64, -64, -65, -63, -64, -64, -63, -64, -64, -64, -64, -64, -64, -64, -64], "mean": -63.8, "variance": 0.56},
    {"x": 22.08, "y": 9.02, "room": "hollway_2nd", "rssi": [-73, -74, -74, -74, -74, -74, -74, -73, -74, -74, -74, -72, -74, -73, -72, -74, -73, -73, -74, -74], "mean": -73.55, "variance": 0.45},
    {"x": 23.9, "y": 1.67, "room": "FT226", "rssi": [-74, -68, -73, -72, -73, -74, -71, -73, -73, -71, -72, -70, -71, -70, -73, -69, -70, -73, -71, -70], "mean": -71.55, "variance": 2.75},
    {"x": 26.53, "y": 5.39, "room": "FT226", "rssi": [-70, -69, -72, -67, -69, -68, -70, -68, -69, -66, -70, -69, -70, -67, -69, -69, -69, -70, -70, -69], "mean": -69, "variance": 1.7},
    {"x": 26.68, "y": 9.03, "room": "stairs_2nd", "rssi": [-76, -80, -80, -80, -76, -80, -80, -79, -79, -73, -71, -79, -77, -52, -79, -80, -52, -80, -80, -79], "mean": -75.6, "variance": 67.84},
    {"x": 30.28, "y": 1.67, "room": "FT227", "rssi": [-75, -75, -54, -77, -75, -75, -78, -73, -76, -75, -77, -76, -75, -77, -76, -75, -64, -75, -75, -64], "mean": -73.35, "variance": 32.83}
];

var wifiStat = [];

function getWifiStatRepeatability() {
    console.log('Wifi_d9')

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
        '<td><div class="groupVariance">' + wifiStat[20].small_mean_variance + '</div></td>' +
        '</tr>';
    $('#wifiTab').append(template)

}
