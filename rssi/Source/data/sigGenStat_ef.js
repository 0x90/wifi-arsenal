var sigGen1 = [
    {"x": 2.02, "y": 10.98, "room": "FT236", "rssi": [-42, -43, -43, -42, -43, -42, -42, -44, -44, -43, -42, -43, -42, -42, -41, -43, -42, -43, -43, -43], "mean": -42.6, "variance": 0.54},
    {"x": 2.17, "y": 4.98, "room": "FT222", "rssi": [-56, -56, -57, -57, -57, -57, -57, -53, -56, -57, -54, -57, -56, -56, -56, -56, -58, -58, -57, -57], "mean": -56.4, "variance": 1.34},
    {"x": 3.51, "y": 9.02, "room": "hollway_2nd", "rssi": [-43, -41, -43, -40, -41, -42, -41, -44, -42, -40, -44, -40, -42, -42, -44, -41, -39, -41, -42, -40], "mean": -41.6, "variance": 2.04},
    {"x": 5.16, "y": 10.94, "room": "FT235", "rssi": [-41, -41, -41, -40, -39, -40, -42, -41, -41, -41, -43, -42, -42, -41, -41, -41, -41, -42, -42, -43], "mean": -41.25, "variance": 0.89},
    {"x": 5.39, "y": 5.06, "room": "FT223", "rssi": [-53, -53, -53, -53, -53, -53, -56, -54, -54, -54, -54, -54, -54, -54, -54, -54, -54, -54, -54], "mean": -53.79, "variance": 0.48},
    {"x": 8.48, "y": 1.93, "room": "FT223", "rssi": [-57, -57, -58, -58, -58, -58, -57, -57, -57, -57, -57, -57, -57, -57, -58, -58, -58, -58], "mean": -57.44, "variance": 0.25},
    {"x": 9.81, "y": 9.02, "room": "hollway_2nd", "rssi": [-54, -54, -55, -55, -54, -54, -59, -55, -59, -59, -59, -54, -53, -56, -60, -50, -56, -55, -55, -55], "mean": -55.55, "variance": 5.95},
    {"x": 11.57, "y": 1.89, "room": "FT224", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 11.57, "y": 5.06, "room": "FT224", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 14.48, "y": 10.95, "room": "FT233", "rssi": [-53, -53, -54, -53, -54, -53, -54, -54, -54, -54, -54, -53, -51, -53, -52, -54, -54, -54, -54, -54], "mean": -53.45, "variance": 0.65},
    {"x": 16.12, "y": 9.02, "room": "hollway_2nd", "rssi": [-61, -61, -62, -62, -63, -62, -62, -62, -62, -62, -63, -62, -62, -62, -62, -62, -62, -61, -61, -60], "mean": -61.8, "variance": 0.46},
    {"x": 17.56, "y": 5.06, "room": "FT225", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 17.59, "y": 10.95, "room": "FT232", "rssi": [-57, -57, -57, -53, -66, -62, -62, -63, -63, -63, -63, -63, -63, -65, -65, -56, -63, -63, -63], "mean": -61.42, "variance": 12.03},
    {"x": 20.54, "y": 10.94, "room": "FT231", "rssi": [-69, -69, -69, -69, -68, -68, -69, -69, -69, -70, -69, -68, -68, -68, -69, -70, -70, -70, -70, -70], "mean": -69.05, "variance": 0.55},
    {"x": 20.71, "y": 1.65, "room": "FT225", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 22.08, "y": 9.02, "room": "hollway_2nd", "rssi": [-65, -65, -65, -67, -67, -67, -67, -69, -68, -68, -68, -68, -68, -68, -68, -68], "mean": -67.25, "variance": 1.44},
    {"x": 23.9, "y": 1.67, "room": "FT226", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 26.53, "y": 5.39, "room": "FT226", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 26.68, "y": 9.03, "room": "stairs_2nd", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 30.28, "y": 1.67, "room": "FT226", "rssi": [], "mean": 'No Data', "variance": 'No Data'}
];

var sigGen2 = [
    {"x": 2.02, "y": 10.98, "room": "FT236", "rssi": [-42, -41, -41, -40, -44, -41, -41, -41, -41, -42, -41, -41, -41, -42, -39, -41, -41, -41, -41, -41], "mean": -41.15, "variance": 0.83},
    {"x": 2.17, "y": 4.98, "room": "FT222", "rssi": [-41, -64, -63, -63, -63, -63, -63, -63, -63, -61, -61, -63, -63, -61, -61, -63, -63, -59, -63, -63], "mean": -61.35, "variance": 23.13},
    {"x": 3.51, "y": 9.02, "room": "hollway_2nd", "rssi": [-59, -61, -60, -62, -61, -61, -60, -63, -60, -61, -61, -62, -61, -67, -61, -61, -61, -61, -61, -61], "mean": -61.25, "variance": 2.39},
    {"x": 5.16, "y": 10.94, "room": "FT235", "rssi": [-44, -45, -45, -44, -44, -45, -46, -45, -45, -43, -45, -43, -43, -44, -45, -45, -44, -45, -46, -45], "mean": -44.55, "variance": 0.75},
    {"x": 5.39, "y": 5.06, "room": "FT223", "rssi": [-50, -50, -50, -55, -55, -51, -52, -51, -51, -51, -50, -50, -50, -55, -55, -56, -51, -51, -51, -51], "mean": -51.8, "variance": 4.16},
    {"x": 8.48, "y": 1.93, "room": "FT223", "rssi": [-57, -57, -57, -57, -60, -60, -60, -60, -60, -57, -59, -59, -59, -60, -60, -57, -57, -57, -57, -57], "mean": -58.35, "variance": 1.93},
    {"x": 9.81, "y": 9.02, "room": "hollway_2nd", "rssi": [-58, -58, -58, -55, -55, -56, -56, -56, -57, -57, -56, -50, -60, -56, -56, -60, -55, -56, -56], "mean": -56.37, "variance": 4.34},
    {"x": 11.57, "y": 5.06, "room": "FT224", "rssi": [-68, -68, -68, -68, -68, -68, -56, -56, -56, -56, -56, -56, -56], "mean": -61.54, "variance": 35.79},
    {"x": 11.57, "y": 1.89, "room": "FT224", "rssi": [-66, -66, -66, -66, -66, -66, -66, -66, -66, -66, -66, -66], "mean": -66, "variance": 0},
    {"x": 14.48, "y": 10.95, "room": "FT233", "rssi": [-57, -57, -55, -61, -61, -57, -58, -58, -49, -58, -58, -58, -58, -57, -58, -59, -59, -58, -58, -51], "mean": -57.25, "variance": 7.59},
    {"x": 16.12, "y": 9.02, "room": "hollway_2nd", "rssi": [-64, -64, -64, -64, -64, -64, -64, -64, -64, -65, -65, -66, -66, -66, -66, -66, -64, -64, -64], "mean": -64.63, "variance": 0.76},
    {"x": 17.56, "y": 5.06, "room": "FT225", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 17.59, "y": 10.95, "room": "FT232", "rssi": [-52, -59, -59, -59, -60, -55, -59, -59, -61, -59, -59, -60, -60, -60, -59, -58, -58], "mean": -58.59, "variance": 4.24},
    {"x": 20.54, "y": 10.94, "room": "FT231", "rssi": [-67, -66, -66, -66, -68, -68, -68, -71, -66, -67, -67, -67, -67, -67, -67, -66, -66, -66, -65], "mean": -66.89, "variance": 1.57},
    {"x": 20.71, "y": 1.65, "room": "FT225", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 22.08, "y": 9.02, "room": "hollway_2nd", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 23.9, "y": 1.67, "room": "FT226", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 26.53, "y": 5.39, "room": "FT226", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 26.68, "y": 9.03, "room": "stairs_2nd", "rssi": [], "mean": 'No Data', "variance": 'No Data'},
    {"x": 30.28, "y": 1.67, "room": "FT227", "rssi": [], "mean": 'No Data', "variance": 'No Data'}
];

var sigGenStat = [];

function getSigGenRepeatability() {
    console.log('SigGen_ef')

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

