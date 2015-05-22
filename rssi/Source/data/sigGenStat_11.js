var sigGen1 = [
    {"x": 2.02, "y": 10.98, "room": "FT236", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 2.17, "y": 4.98, "room": "FT222", "rssi": [-76, -76, -76, -76], "mean": -76, "variance": 0},
    {"x": 3.51, "y": 9.02, "room": "hollway_2nd", "rssi": [-73, -70, -74, -71, -71, -71, -71, -71, -71, -71, -71, -71, -71, -71, -71, -71, -71, -71, -71, -71], "mean": -71.2, "variance": 0.66},
    {"x": 5.16, "y": 10.94, "room": "FT235", "rssi": [-85, -85, -85, -86, -86, -86, -86, -87, -87, -87, -87, -87, -87, -87, -85], "mean": -86.2, "variance": 0.69},
    {"x": 5.39, "y": 5.06, "room": "FT223", "rssi": [-64], "mean": -64, "variance": 0},
    {"x": 8.48, "y": 1.93, "room": "FT223", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 9.81, "y": 9.02, "room": "hollway_2nd", "rssi": [-70, -70, -70, -70, -70, -70, -70, -70, -70, -73, -73, -73, -73, -73, -73, -73, -70, -70, -73, -73], "mean": -71.35, "variance": 2.23},
    {"x": 11.57, "y": 1.89, "room": "FT224", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 11.57, "y": 5.06, "room": "FT224", "rssi": [-53, -53, -53, -53, -53, -55, -55, -55, -55, -55, -55, -55, -55, -59, -59, -59, -59], "mean": -55.35, "variance": 4.82},
    {"x": 14.48, "y": 10.95, "room": "FT233", "rssi": [-77, -77, -48, -48, -48, -48, -48, -48, -48, -48, -48, -48, -48], "mean": -52.46, "variance": 109.48},
    {"x": 16.12, "y": 9.02, "room": "hollway_2nd", "rssi": [-73, -73, -73, -73, -73, -73, -73, -73, -73, -73], "mean": -73, "variance": 0},
    {"x": 17.56, "y": 5.06, "room": "FT225", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 17.59, "y": 10.95, "room": "FT232", "rssi": [-71, -71, -71, -71, -69, -69, -69, -69, -69, -69, -69, -69, -69, -69, -69, -69, -69, -69, -69, -69], "mean": -69.4, "variance": 0.64},
    {"x": 20.54, "y": 10.94, "room": "FT231", "rssi": [-70, -70, -70, -70, -71, -71, -71, -71, -71, -71, -71, -71], "mean": -70.67, "variance": 0.22},
    {"x": 20.71, "y": 1.65, "room": "FT225", "rssi": [-52, -52, -52, -52, -52, -52, -52, -52, -52, -52, -52, -52, -52, -52, -52, -52], "mean": -52, "variance": 0},
    {"x": 22.08, "y": 9.02, "room": "hollway_2nd", "rssi": [-57, -57, -57, -57, -57, -57, -57, -57, -57, -57, -57, -57, -57, -57, -57, -57, -57], "mean": -57, "variance": 0},
    {"x": 23.9, "y": 1.67, "room": "FT226", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 26.53, "y": 5.39, "room": "FT226", "rssi": [-40, -40, -40, -40, -40, -40, -40, -40, -40, -40, -40, -40, -40, -40, -40, -40, -40, -40, -40], "mean": -40, "variance": 0},
    {"x": 26.68, "y": 9.03, "room": "stairs_2nd", "rssi": [-56, -56, -56, -56, -56, -56, -56], "mean": -56, "variance": 0},
    {"x": 30.28, "y": 1.67, "room": "FT226", "rssi": [-27, -53, -53, -53, -53, -58, -68, -29, -52, -52, -52, -64, -26, -64, -40, -68, -25, -44, -25], "mean": -47.68, "variance": 209.58}
];

var sigGen2 = [
    {"x": 2.02, "y": 10.98, "room": "FT236", "rssi": [-77, -77, -77], "mean": -77, "variance": 0},
    {"x": 2.17, "y": 4.98, "room": "FT222", "rssi": [-74, -74, -74, -74, -74, -74, -74, -74, -74, -74, -74, -74, -74, -74, -74], "mean": -74, "variance": 0},
    {"x": 3.51, "y": 9.02, "room": "hollway_2nd", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 5.16, "y": 10.94, "room": "FT235", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 5.39, "y": 5.06, "room": "FT223", "rssi": [-67, -67, -67, -67, -68, -68, -68, -68, -68, -68, -68, -68], "mean": -67.67, "variance": 0.22},
    {"x": 8.48, "y": 1.93, "room": "FT223", "rssi": [-66, -66, -66, -66, -53, -53, -53, -53, -53, -53, -53, -53, -53, -53, -53, -53, -53, -53, -53], "mean": -55.74, "variance": 28.09},
    {"x": 9.81, "y": 9.02, "room": "hollway_2nd", "rssi": [-68, -68, -68, -68, -68, -68, -67, -67, -68, -68, -68, -68, -68, -68, -68], "mean": -67.87, "variance": 0.12},
    {"x": 11.57, "y": 5.06, "room": "FT224", "rssi": [-55, -55, -55, -55, -55, -55, -55, -55, -55, -55, -55, -55, -55, -55, -55, -54], "mean": -54.94, "variance": 0.06},
    {"x": 11.57, "y": 1.89, "room": "FT224", "rssi": [-54, -54, -54, -54], "mean": -54, "variance": 0},
    {"x": 14.48, "y": 10.95, "room": "FT233", "rssi": [-79, -79, -79, -79, -79, -79, -76], "mean": -78.57, "variance": 1.1},
    {"x": 16.12, "y": 9.02, "room": "hollway_2nd", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 17.56, "y": 5.06, "room": "FT225", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 17.59, "y": 10.95, "room": "FT232", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 20.54, "y": 10.94, "room": "FT231", "rssi": [-68, -68, -68, -68, -68, -68], "mean": -68, "variance": 0},
    {"x": 20.71, "y": 1.65, "room": "FT225", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 22.08, "y": 9.02, "room": "hollway_2nd", "rssi": [-54, -54, -54, -54, -54, -54, -54, -54, -54, -54, -54, -54, -54, -54, -55], "mean": -54.07, "variance": 0.06},
    {"x": 23.9, "y": 1.67, "room": "FT226", "rssi": [-46, -46, -46, -46, -46, -46, -46, -46, -46, -46], "mean": -46, "variance": 0},
    {"x": 26.53, "y": 5.39, "room": "FT226", "rssi": [-38, -38, -38, -38, -38, -38, -38, -38, -38, -38, -38, -38, -38], "mean": -38, "variance": 0},
    {"x": 26.68, "y": 9.03, "room": "stairs_2nd", "rssi": [-53, -53, -53, -58, -58, -58, -58, -58, -58, -58, -58, -58, -57, -57, -53, -53, -53, -53, -53], "mean": -55.79, "variance": 5.75},
    {"x": 30.28, "y": 1.67, "room": "FT227", "rssi": [-60, -60, -44, -70, -25, -70, -70, -49, -49, -45, -53, -53, -44, -44, -62, -62, -45, -40, -40, -40], "mean": -51.25, "variance": 137.99}
];

var sigGenStat = [];

function getSigGenRepeatability() {
    console.log('SigGen_11')

    $.each(sigGen1, function (key, val) {
        if (val.mean != 'No Data') {
            val.mean = val.mean;
        }

        sigGenStat.push({
            'x': val.x,
            'y': val.y,
            'small01_variance': val.variance,
            'small01_mean': val.mean,
            'rssi': val.rssi,
            'room': val.room
        })
    });

    $.each(sigGen2, function (key, val) {

        if (val.mean != 'No Data') {
            val.mean = val.mean * -1;
        }

        sigGenStat[key].small02_mean = val.mean;
        sigGenStat[key].small02_variance = val.variance;
        sigGenStat[key].rssi = sigGenStat[key].rssi.concat(val.rssi)
    });

    $.each(sigGenStat, function (key, val) {
        if (val.rssi.length != 0) {
            sigGenStat[key].groupVariance = d3.round(app.utils.statisticsCalculator(val.rssi).variance, 2)
        } else {
            sigGenStat[key].groupVariance = 'No Data'
        }
    })

    sigGenStat.push({
        'small01_mean_variance': [],
        'small02_mean_variance': [],

        'small01_avg_mean': [],
        'small02_avg_mean': [],

        'small_mean_variance': []
    })
    $.each(sigGenStat, function (key, val) {
        if (key != 20) {
            if (val.small01_variance != 'No Data'
                && val.small01_mean != 'No Data') {
                sigGenStat[20].small01_mean_variance.push(val.small01_variance);
                sigGenStat[20].small01_avg_mean.push(val.small01_mean);
            }

            if (val.small02_variance != 'No Data'
                && val.small02_mean != 'No Data') {
                sigGenStat[20].small02_mean_variance.push(val.small02_variance);
                sigGenStat[20].small02_avg_mean.push(val.small02_mean);
            }

            if (val.groupVariance != 'No Data') {
                sigGenStat[20].small_mean_variance.push(val.groupVariance);
            }
        }

    })

    sigGenStat[20].small01_mean_variance = d3.round(app.utils.statisticsCalculator(sigGenStat[20].small01_mean_variance).mean, 2)
    sigGenStat[20].small02_mean_variance = d3.round(app.utils.statisticsCalculator(sigGenStat[20].small02_mean_variance).mean, 2)

    sigGenStat[20].small01_avg_mean = d3.round(app.utils.statisticsCalculator(sigGenStat[20].small01_avg_mean).mean, 2)
    sigGenStat[20].small02_avg_mean = d3.round(app.utils.statisticsCalculator(sigGenStat[20].small02_avg_mean).mean, 2)

    sigGenStat[20].small_mean_variance = d3.round(app.utils.statisticsCalculator(sigGenStat[20].small_mean_variance).mean, 2)

    var template = "<tr>" +
        "<td>Measurement Points</td>" +
        "<td>Room</td>" +
        "<td>X in meters</td>" +
        "<td>Y in meters</td>" +
        "<td>Experiment01 Variance</td><td>Experiment01 Mean in dBm</td>" +
        "<td>Experiment02 Variance</td><td>Experiment02 Mean in dBm</td>" +
        "<td>Group Variance</td>" +
        "</tr>";

    $('#sigGenTab').append(template)

    var data1m = [];
    var data2m = [];
    var data1v = [];
    var data2v = [];
    var dataGv = [];

    var i = 1;
    $.each(sigGenStat, function (key, val) {
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

            $('#sigGenTab').append(template)
            i++;
        }
    });

    console.log("% SigGen_Mean")
    console.log("zSig_Ex_1_Mean = {" + data1m + "};")
    console.log("zSig_Ex_2_Mean = {" + data2m + "};")
    console.log("% SigGen_Variance")
    console.log("zSig_Ex_1_Var = {" + data1v + "};")
    console.log("zSig_Ex_2_Var = {" + data2v + "};")
    console.log("% SigGen_GVariance")
    console.log("Sig_Ex_Group_Var = {" + dataGv + "};")

    template = '<tr>' +
        '<td>' + 'Average' + '</td>' +
        '<td>' + ' ' + '</td>' +
        '<td>' + ' ' + '</td>' +
        '<td>' + ' ' + '</td>' +
        '<td>' + sigGenStat[20].small01_mean_variance + '</td>' +
        '<td>' + ' ' + '</td>' +
        '<td>' + sigGenStat[20].small02_mean_variance + '</td>' +
        '<td>' + ' ' + '</td>' +
        '<td><div class="groupVariance">' + sigGenStat[20].small_mean_variance + '</div></td>' +
        '</tr>';
    $('#sigGenTab').append(template)

}

