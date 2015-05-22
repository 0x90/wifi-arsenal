var wifiStat1 = [
    {"x": 2.02, "y": 10.98, "room": "FT236", "rssi": [-64, -53, -49, -54, -54, -48, -53, -59, -70, -53, -54, -53, -51, -54, -52, -51, -54, -52, -54, -48], "mean": -54, "variance": 25.4},
    {"x": 2.17, "y": 4.98, "room": "FT222", "rssi": [-58, -60, -54, -58, -59, -55, -58, -58, -59, -58, -58, -58, -58, -58, -58, -58, -58, -58, -55, -54], "mean": -57.5, "variance": 2.55},
    {"x": 3.51, "y": 9.02, "room": "hollway_2nd", "rssi": [-47, -44, -50, -47, -48, -47, -47, -46, -47, -47, -52, -46, -50, -47, -48, -52, -47, -47, -51, -48], "mean": -47.9, "variance": 4.09},
    {"x": 5.16, "y": 10.94, "room": "FT235", "rssi": [-45, -44, -44, -44, -44, -44, -46, -45, -44, -45, -45, -45, -44, -62, -44, -44, -45, -45, -44, -42], "mean": -45.25, "variance": 15.39},
    {"x": 5.39, "y": 5.06, "room": "FT223", "rssi": [-52, -53, -52, -54, -52, -51, -52, -54, -52, -54, -52, -55, -54, -52, -55, -52, -52, -52, -52, -66], "mean": -53.4, "variance": 9.64},
    {"x": 8.48, "y": 1.93, "room": "FT223", "rssi": [-58, -58, -60, -58, -58, -60, -58, -57, -60, -58, -58, -59, -58, -58, -59, -57, -58, -58, -57, -58], "mean": -58.25, "variance": 0.79},
    {"x": 9.81, "y": 9.02, "room": "hollway_2nd", "rssi": [-52, -51, -49, -51, -51, -47, -51, -51, -51, -47, -47, -51, -51, -51, -50, -51, -51, -50, -47, -51], "mean": -50.05, "variance": 2.65},
    {"x": 11.57, "y": 5.06, "room": "FT224", "rssi": [-69, -70, -68, -69, -69, -68, -69, -69, -70, -69, -69, -70, -69, -69, -68, -70, -69, -69, -70, -68], "mean": -69.05, "variance": 0.45},
    {"x": 11.57, "y": 1.89, "room": "FT224", "rssi": [-72, -74, -72, -73, -74, -75, -73, -68, -48, -75, -73, -72, -75, -73, -72, -75, -73, -72, -75, -73], "mean": -71.85, "variance": 32.53},
    {"x": 14.48, "y": 10.95, "room": "FT233", "rssi": [-55, -55, -54, -54, -55, -54, -55, -55, -54, -55, -57, -52, -54, -79, -54, -55, -54, -55, -55, -54], "mean": -55.75, "variance": 29.29},
    {"x": 16.12, "y": 9.02, "room": "hollway_2nd", "rssi": [-71, -65, -62, -65, -64, -64, -65, -69, -67, -65, -63, -65, -65, -71, -65, -65, -71, -66, -57, -65], "mean": -65.5, "variance": 10.15},
    {"x": 17.56, "y": 5.06, "room": "FT225", "rssi": [-79, -82, -79, -80, -82, -90, -80, -82, -90, -82, -79, -80, -82, -79, -80, -82, -82, -79, -82, -79], "mean": -81.5, "variance": 9.65},
    {"x": 17.59, "y": 10.95, "room": "FT232", "rssi": [-67, -67, -67, -70, -66, -68, -70, -64, -66, -53, -53, -67, -67, -68, -67, -63, -67, -67, -66, -65], "mean": -65.4, "variance": 19.64},
    {"x": 20.54, "y": 10.94, "room": "FT231", "rssi": [-66, -50, -66, -66, -67, -65, -66, -61, -54, -66, -64, -66, -65, -63, -62, -65, -64, -65], "mean": -63.39, "variance": 18.9},
    {"x": 20.71, "y": 1.65, "room": "FT225", "rssi": [-83, -81, -82, -81, -81, -82, -81, -83, -82, -81, -83, -81, -81, -83, -81, -81, -83, -81, -82], "mean": -81.74, "variance": 0.72},
    {"x": 22.08, "y": 9.02, "room": "hollway_2nd", "rssi": [-69, -72, -68, -69, -72, -72, -69, -75, -69, -72, -75, -69, -75, -72, -75, -75, -72, -69, -75, -68], "mean": -71.6, "variance": 6.84},
    {"x": 23.9, "y": 1.67, "room": "FT226", "rssi": [-86, -88, -87, -86, -88, -86, -88, -88, -86, -88, -88, -87, -88, -88, -87, -86, -88, -87], "mean": -87.22, "variance": 0.73},
    {"x": 26.53, "y": 5.39, "room": "FT226", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 26.68, "y": 9.03, "room": "stairs_2nd", "rssi": [-76, -75, -76, -76, -76, -76, -76, -76, -76, -76, -76, -75, -76, -76, -76, -76, -76], "mean": -75.88, "variance": 0.1},
    {"x": 30.28, "y": 1.67, "room": "FT227", "rssi": [], "mean": 'No Data', "variance": 'No Data'}
];

var wifiStat2 = [
    {"x": 2.02, "y": 10.98, "room": "FT236", "rssi": [-52, -84, -54, -49, -52, -52, -46, -53, -55, -51, -51, -53, -52, -53, -53, -52, -49, -53, -52, -50], "mean": -53.3, "variance": 53.41},
    {"x": 2.17, "y": 4.98, "room": "FT222", "rssi": [-51, -54, -53, -51, -53, -53, -53, -53, -53, -53, -54, -53, -52, -53, -54, -53, -53, -54, -55, -53], "mean": -53.05, "variance": 0.85},
    {"x": 3.51, "y": 9.02, "room": "hollway_2nd", "rssi": [-46, -50, -47, -49, -54, -48, -51, -49, -48, -48, -49, -48, -54, -46, -79, -48, -46, -47, -50, -48], "mean": -50.25, "variance": 48.29},
    {"x": 5.16, "y": 10.94, "room": "FT235", "rssi": [-36, -35, -35, -36, -35, -36, -36, -35, -35, -36, -35, -36, -35, -35, -35, -80, -36, -36, -36, -35], "mean": -37.7, "variance": 94.41},
    {"x": 5.39, "y": 5.06, "room": "FT223", "rssi": [-50, -50, -51, -51, -52, -51, -50, -50, -51, -51, -50, -50, -51, -51, -51, -53, -51, -50, -54, -51], "mean": -50.95, "variance": 1.05},
    {"x": 8.48, "y": 1.93, "room": "FT223", "rssi": [-61, -60, -58, -61, -50, -61, -60, -60, -46, -61, -61, -60, -60, -61, -62, -60, -59, -62, -60, -61], "mean": -59.2, "variance": 15.16},
    {"x": 9.81, "y": 9.02, "room": "hollway_2nd", "rssi": [-60, -60, -59, -60, -60, -59, -57, -59, -61, -60, -59, -65, -59, -59, -59, -61, -60, -59, -61, -59], "mean": -59.8, "variance": 2.26},
    {"x": 11.57, "y": 5.06, "room": "FT224", "rssi": [-66, -65, -66, -64, -65, -67, -64, -67, -69, -65, -66, -69, -67, -69, -69, -67, -69, -66, -66], "mean": -66.63, "variance": 2.76},
    {"x": 11.57, "y": 1.89, "room": "FT224", "rssi": [-63, -64, -63, -65, -64, -64, -64, -64, -64, -64, -64, -64, -64, -64, -64, -64, -64, -63, -68, -47], "mean": -63.25, "variance": 14.89},
    {"x": 14.48, "y": 10.95, "room": "FT233", "rssi": [-51, -50, -83, -50, -49, -51, -51, -50, -49, -48, -50, -51, -50, -51, -50, -51, -83, -51, -51, -50], "mean": -53.5, "variance": 97.35},
    {"x": 16.12, "y": 9.02, "room": "hollway_2nd", "rssi": [-61, -64, -64, -64, -64, -64, -64, -62, -67, -64, -64, -63, -64, -64, -63, -62, -64, -63, -62, -64], "mean": -63.55, "variance": 1.45},
    {"x": 17.56, "y": 5.06, "room": "FT225", "rssi": [-70, -48, -71, -70, -70, -71, -71, -72, -70, -71, -70, -70, -70, -70, -51, -70, -70, -51, -48, -71], "mean": -66.25, "variance": 70.89},
    {"x": 17.59, "y": 10.95, "room": "FT232", "rssi": [-64, -75, -63, -64, -70, -64, -64, -63, -63, -63, -64, -64, -63, -63, -63, -63, -69, -63, -63, -63], "mean": -64.55, "variance": 9.35},
    {"x": 20.54, "y": 10.94, "room": "FT231", "rssi": [-63, -62, -63, -63, -62, -63, -64, -62, -63, -61, -63, -63, -63, -63, -63, -63, -63, -62, -63, -62], "mean": -62.7, "variance": 0.41},
    {"x": 20.71, "y": 1.65, "room": "FT225", "rssi": [-85, -85, -84, -85, -85, -84, -85, -85, -85, -87, -85, -87, -85, -87, -85, -85, -87], "mean": -85.35, "variance": 0.93},
    {"x": 22.08, "y": 9.02, "room": "hollway_2nd", "rssi": [-69, -69, -70, -69, -69, -69, -69, -69, -68, -53, -69, -69, -70, -69, -68, -69, -70, -69, -69, -70], "mean": -68.3, "variance": 12.61},
    {"x": 23.9, "y": 1.67, "room": "FT226", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 26.53, "y": 5.39, "room": "FT226", "rssi": [-85, -78, -84, -85, -86, -84, -85, -86, -84, -85, -85, -84, -84, -85, -78, -84, -85, -78, -84], "mean": -83.63, "variance": 6.34},
    {"x": 26.68, "y": 9.03, "room": "stairs_2nd", "rssi": [-75, -79, -48, -77, -79, -77, -76, -77, -74, -77, -74, -79, -71, -74, -79, -76], "mean": -74.5, "variance": 51.63},
    {"x": 30.28, "y": 1.67, "room": "FT227", "rssi": [-88, -88, -88], "mean": -88, "variance": 0}
];

var wifiStat = [];

function getWifiStatRepeatability() {
    console.log('Wifi_ef')

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
