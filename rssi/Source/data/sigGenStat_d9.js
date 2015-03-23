var sigGen1 = [
    {"x": 2.02, "y": 10.98, "room": "FT236", "rssi": [-52, -52, -52, -50, -50, -52, -53, -56, -52, -49, -53, -53, -52, -53, -50, -52, -53, -52, -50, -53], "mean": -51.95, "variance": 2.35},
    {"x": 2.17, "y": 4.98, "room": "FT222", "rssi": [-39, -39, -39, -40, -39, -39, -40, -39, -39, -40, -40, -42, -39, -40, -41, -43, -40, -40, -40, -40], "mean": -39.9, "variance": 1.09},
    {"x": 3.51, "y": 9.02, "room": "hollway_2nd", "rssi": [-56, -55, -72, -56, -56, -56, -57, -56, -56, -56, -57, -56, -56, -56, -59, -56, -57, -56, -56, -59], "mean": -57.2, "variance": 12.46},
    {"x": 5.16, "y": 10.94, "room": "FT235", "rssi": [-59, -59, -59, -65, -59, -60, -62, -60, -59, -60, -60, -60, -62, -60, -67, -60, -60, -57, -60, -62], "mean": -60.5, "variance": 4.75},
    {"x": 5.39, "y": 5.06, "room": "FT223", "rssi": [-49, -45, -45, -45, -45, -45, -49, -47, -45, -45, -45, -45, -54, -45, -45, -45, -45, -45, -45], "mean": -46, "variance": 5.16},
    {"x": 8.48, "y": 1.93, "room": "FT223", "rssi": [-40, -45, -40, -40, -41, -40, -45, -40, -42, -41, -40, -40, -40, -46, -40, -40, -40, -42], "mean": -41.22, "variance": 3.84},
    {"x": 9.81, "y": 9.02, "room": "hollway_2nd", "rssi": [-64, -64, -64, -64, -64, -64, -64, -64, -65, -65, -65, -65, -64, -64, -64, -64, -64, -64, -64, -64], "mean": -64.2, "variance": 0.16},
    {"x": 11.57, "y": 1.89, "room": "FT224", "rssi": [-54, -54, -53, -53, -54, -54, -54, -54, -54, -55, -55, -55, -55, -55, -55, -55, -55, -55, -55, -55], "mean": -54.45, "variance": 0.45},
    {"x": 11.57, "y": 5.06, "room": "FT224", "rssi": [-59, -59, -59, -59, -59, -59, -59, -59, -59, -59, -59, -59, -59, -59, -57, -57], "mean": -58.75, "variance": 0.44},
    {"x": 14.48, "y": 10.95, "room": "FT233", "rssi": [-72, -68, -68, -63, -68, -68, -68, -67, -68, -67, -68, -67, -67, -67, -66, -68, -68, -68, -68, -67], "mean": -67.55, "variance": 2.35},
    {"x": 16.12, "y": 9.02, "room": "hollway_2nd", "rssi": [-69, -69, -69, -69, -69, -69, -69, -71, -71, -71, -71, -71, -55, -55, -55, -71, -71, -71], "mean": -67.56, "variance": 32.36},
    {"x": 17.56, "y": 5.06, "room": "FT225", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 17.59, "y": 10.95, "room": "FT232", "rssi": [-75, -75, -70, -70, -70, -70, -70, -70, -70, -77, -69, -69, -69, -69, -78, -78, -78, -78, -78, -78], "mean": -73.05, "variance": 15.05},
    {"x": 20.54, "y": 10.94, "room": "FT231", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 20.71, "y": 1.65, "room": "FT225", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 22.08, "y": 9.02, "room": "hollway_2nd", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 23.9, "y": 1.67, "room": "FT226", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 26.53, "y": 5.39, "room": "FT226", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 26.68, "y": 9.03, "room": "stairs_2nd", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 30.28, "y": 1.67, "room": "FT226", "rssi": [], "mean": 'No Data', "variance": 'No Data'}
];

var sigGen2 = [
    {"x": 2.02, "y": 10.98, "room": "FT236", "rssi": [-50, -51, -53, -50, -52, -50, -50, -50, -50, -51, -50, -51, -50, -50, -51, -50, -51, -49, -50, -50], "mean": -50.45, "variance": 0.75},
    {"x": 2.17, "y": 4.98, "room": "FT222", "rssi": [-37, -41, -38, -37, -37, -37, -38, -37, -37, -37, -37, -37, -38, -64, -37, -38, -38, -37, -37, -37], "mean": -38.8, "variance": 34.26},
    {"x": 3.51, "y": 9.02, "room": "hollway_2nd", "rssi": [-53, -54, -48, -54, -51, -51, -51, -52, -51, -49, -50, -51, -51, -50, -52, -51, -52, -51, -51, -51], "mean": -51.2, "variance": 1.96},
    {"x": 5.16, "y": 10.94, "room": "FT235", "rssi": [-52, -57, -57, -52, -52, -53, -53, -55, -53, -53, -52, -52, -53, -52, -53, -52, -53, -53, -53, -53], "mean": -53.15, "variance": 2.13},
    {"x": 5.39, "y": 5.06, "room": "FT223", "rssi": [-38, -37, -37, -38, -42, -37, -38, -38, -37, -38, -40, -36, -36, -36, -34, -38, -38, -38, -38], "mean": -37.58, "variance": 2.56},
    {"x": 8.48, "y": 1.93, "room": "FT223", "rssi": [-51, -51, -49, -48, -51, -51, -50, -49, -49, -49, -49, -49, -49, -54, -49, -49, -49, -49, -51], "mean": -49.79, "variance": 1.85},
    {"x": 9.81, "y": 9.02, "room": "hollway_2nd", "rssi": [-53, -53, -53, -56, -53, -51, -54, -54, -54, -53, -54, -54, -54, -54, -54, -54, -52, -54, -54, -54], "mean": -53.6, "variance": 0.94},
    {"x": 11.57, "y": 5.06, "room": "FT224", "rssi": [-57, -57, -58, -58, -58, -58, -58, -58, -58, -58, -56, -56, -56, -56, -56, -56, -56, -56, -56, -56], "mean": -56.9, "variance": 0.89},
    {"x": 11.57, "y": 1.89, "room": "FT224", "rssi": [-52], "mean": -52, "variance": 0},
    {"x": 14.48, "y": 10.95, "room": "FT233", "rssi": [-72, -71, -71, -72, -72, -72, -73, -72, -72, -72, -72, -73, -73, -73, -73, -73, -68, -68, -68, -72], "mean": -71.6, "variance": 2.64},
    {"x": 16.12, "y": 9.02, "room": "hollway_2nd", "rssi": [-51, -51, -51, -51], "mean": -51, "variance": 0},
    {"x": 17.56, "y": 5.06, "room": "FT225", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 17.59, "y": 10.95, "room": "FT232", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 20.54, "y": 10.94, "room": "FT231", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 20.71, "y": 1.65, "room": "FT225", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 22.08, "y": 9.02, "room": "hollway_2nd", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 23.9, "y": 1.67, "room": "FT226", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 26.53, "y": 5.39, "room": "FT226", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 26.68, "y": 9.03, "room": "stairs_2nd", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 30.28, "y": 1.67, "room": "FT227", "rssi": [], "mean": 'No Data', "variance": 'No Data'}
];

var sigGenStat = [];

function getSigGenRepeatability() {
    console.log('SigGen_d9')

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

