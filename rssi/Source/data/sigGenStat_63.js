var sigGen1 = [
    {"x": 2.02, "y": 10.98, "room": "FT236", "rssi": [-72, -72, -74, -69, -69, -74, -74, -74, -74, -75, -75, -75, -75, -74, -74, -75, -74, -74, -71, -74], "mean": -73.4, "variance": 3.24},
    {"x": 2.17, "y": 4.98, "room": "FT222", "rssi": [-80, -80, -80, -80, -81, -81, -81, -81, -83, -81, -81, -82, -81], "mean": -80.92, "variance": 0.69},
    {"x": 3.51, "y": 9.02, "room": "hollway_2nd", "rssi": [-72, -74, -75, -72, -75, -75, -79, -73, -75, -73, -74, -74, -74, -74, -74, -73, -73, -75, -74, -75], "mean": -74.15, "variance": 2.13},
    {"x": 5.16, "y": 10.94, "room": "FT235", "rssi": [-63, -68, -68, -68, -64, -65, -62, -68, -65, -64, -65, -63, -64, -64, -68, -65, -64, -66, -66, -65], "mean": -65.25, "variance": 3.39},
    {"x": 5.39, "y": 5.06, "room": "FT223", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 8.48, "y": 1.93, "room": "FT223", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 9.81, "y": 9.02, "room": "hollway_2nd", "rssi": [-62, -63, -64, -63, -63, -64, -64, -64, -64, -64, -63, -65, -65, -65, -64, -68, -64, -65, -65, -68], "mean": -64.35, "variance": 2.13},
    {"x": 11.57, "y": 1.89, "room": "FT224", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 11.57, "y": 5.06, "room": "FT224", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 14.48, "y": 10.95, "room": "FT233", "rssi": [-49, -48, -48, -49, -50, -54, -49, -49, -49, -47, -48, -50, -67, -76, -49, -49, -50, -49, -48, -48], "mean": -51.3, "variance": 49.21},
    {"x": 16.12, "y": 9.02, "room": "hollway_2nd", "rssi": [-48, -46, -46, -48, -47, -47, -52, -47, -48, -48, -48, -51, -46, -46, -48, -48, -47, -47, -47, -48], "mean": -47.65, "variance": 2.23},
    {"x": 17.56, "y": 5.06, "room": "FT225", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 17.59, "y": 10.95, "room": "FT232", "rssi": [-44, -46, -46, -44, -48, -48, -47, -46, -47, -48, -47, -46, -47, -47, -47, -47, -46, -47, -47, -48], "mean": -46.65, "variance": 1.23},
    {"x": 20.54, "y": 10.94, "room": "FT231", "rssi": [-39, -39, -40, -43, -39, -39, -40, -39, -40, -39, -40, -40, -38, -39, -39, -40, -40, -40, -39, -40], "mean": -39.6, "variance": 0.94},
    {"x": 20.71, "y": 1.65, "room": "FT225", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 22.08, "y": 9.02, "room": "hollway_2nd", "rssi": [-51, -47, -47, -51, -50, -51, -51, -51, -51, -46, -49, -49, -46, -46, -46, -46, -47, -51, -47], "mean": -48.58, "variance": 4.56},
    {"x": 23.9, "y": 1.67, "room": "FT226", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 26.53, "y": 5.39, "room": "FT226", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 26.68, "y": 9.03, "room": "stairs_2nd", "rssi": [-60, -60, -60, -60, -60, -60, -59, -57, -58, -58, -58, -58, -58, -58, -58, -58, -58], "mean": -58.71, "variance": 1.03},
    {"x": 30.28, "y": 1.67, "room": "FT226", "rssi": [], "mean": 'No Data', "variance": 'No Data'}
];

var sigGen2 = [
    {"x": 2.02, "y": 10.98, "room": "FT236", "rssi": [-72, -77, -77, -77, -77, -77, -77, -78, -76, -78, -78, -78, -78, -78, -78, -78, -77, -77, -65, -65], "mean": -75.9, "variance": 14.89},
    {"x": 2.17, "y": 4.98, "room": "FT222", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 3.51, "y": 9.02, "room": "hollway_2nd", "rssi": [-67, -68, -68, -67, -68, -68, -68, -68, -68, -68, -68, -68, -68, -68, -68, -68, -68, -68, -68], "mean": -67.89, "variance": 0.09},
    {"x": 5.16, "y": 10.94, "room": "FT235", "rssi": [-64, -66, -65, -65, -65, -65, -65, -65, -65, -65, -66, -65, -66, -65, -64, -65, -66, -65, -69], "mean": -65.32, "variance": 1.06},
    {"x": 5.39, "y": 5.06, "room": "FT223", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 8.48, "y": 1.93, "room": "FT223", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 9.81, "y": 9.02, "room": "hollway_2nd", "rssi": [-65, -65, -65, -64, -65, -66, -65, -65, -65, -66, -66, -66, -66, -63, -63, -63, -65, -65, -65, -66], "mean": -64.95, "variance": 0.95},
    {"x": 11.57, "y": 5.06, "room": "FT224", "rssi": [-62, -62, -62, -62, -62, -62, -62, -62, -62, -62, -62, -62, -62, -62, -62, -62, -62, -62, -62, -62], "mean": -62, "variance": 0},
    {"x": 11.57, "y": 1.89, "room": "FT224", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 14.48, "y": 10.95, "room": "FT233", "rssi": [-53, -53, -53, -53, -53, -53, -53, -54, -54, -52, -54, -54, -54, -53, -54, -53, -55, -53, -54, -53], "mean": -53.4, "variance": 0.44},
    {"x": 16.12, "y": 9.02, "room": "hollway_2nd", "rssi": [-53, -53, -53, -53, -53, -53, -53, -53, -53, -53, -53, -53, -53, -53, -53, -53, -53, -53], "mean": -53, "variance": 0},
    {"x": 17.56, "y": 5.06, "room": "FT225", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 17.59, "y": 10.95, "room": "FT232", "rssi": [-47, -47, -47, -47, -48, -47, -47, -47, -47, -47, -47, -47, -47, -47, -47, -47, -48, -47, -48, -47], "mean": -47.15, "variance": 0.13},
    {"x": 20.54, "y": 10.94, "room": "FT231", "rssi": [-45, -32, -32, -32, -32, -32, -32, -32, -32, -32, -32, -32, -32, -32, -32, -33, -32, -33, -32, -32], "mean": -32.75, "variance": 7.99},
    {"x": 20.71, "y": 1.65, "room": "FT225", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 22.08, "y": 9.02, "room": "hollway_2nd", "rssi": [-47, -47, -53, -53, -53, -53, -50, -50, -50, -50, -50, -50, -50, -50, -50, -50, -50, -50, -50, -50], "mean": -50.3, "variance": 2.61},
    {"x": 23.9, "y": 1.67, "room": "FT226", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 26.53, "y": 5.39, "room": "FT226", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 26.68, "y": 9.03, "room": "stairs_2nd", "rssi": [-61, -61, -61, -61, -62, -60, -61, -61, -61, -61, -61, -61, -61], "mean": -61, "variance": 0.15},
    {"x": 30.28, "y": 1.67, "room": "FT227", "rssi": [], "mean": 'No Data', "variance": 'No Data'}
];

var sigGenStat = [];

function getSigGenRepeatability() {
    console.log('SigGen_63')

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
            val.mean = val.mean;
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

