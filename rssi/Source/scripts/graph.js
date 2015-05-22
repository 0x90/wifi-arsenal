/**
* Graph gets an Array of RSSI values and draws a Histogram using D3.JS
*
* @class graph
*/
app.graph = {

    /**
     It draws the SVG based Graph
     @method draw
     @param {Array} rssi RSSI values of the selected accesspoint
     **/
    draw: function (values) {

        app.view.clearGraph()

        var width = 930;
        var height = 470;
        var padding = 60;
        var barWidth = 30;

        var startValue = d3.max(values);
        var endValue = d3.min(values);
        var binTicks = 10;

        if ((startValue - endValue) > 10) {
            binTicks = startValue - endValue
        } else {
            startValue += 9 - (startValue - endValue)
        }

        var x = d3.scale.linear()
            .domain([ startValue + 1 , endValue - 1])
            .range([0, width - 2 * padding]);

        var data = d3.layout.histogram()
            .bins(x.ticks(binTicks))
            (values);

        var y = d3.scale.linear()
            .domain([0, d3.max(data, function (d) {
                return d.y + 1;
            })])
            .range([height - 2 * padding, 0]);


        var xAxis = d3.svg.axis();

        xAxis.scale(x)
            .orient("bottom");

        xAxis.ticks(binTicks)

        var yAxis = d3.svg.axis();

        yAxis.scale(y)
            .orient("left");

        yAxis.ticks(d3.max(data, function (d) {
            return d.y + 1;
        }));

        var svg = d3.select("#graph").append("svg")
            .attr("width", width)
            .attr("height", height)

        var bar = svg.selectAll(".bar")
            .data(data)
            .enter()
            .append("g")
            .attr("class", "bar");

        bar.append("rect")
            .attr("x", function (d) {
                return x(d.x) + padding - (barWidth / 2)
            })
            .attr("y", height)
            .attr("width", barWidth)
            .transition()
            .delay(function (d, i) {
                return i * 50;
            })
            .duration(500)
            .attr("height", function (d) {
                return height - 2 * padding - y(d.y);
            })
            .attr("y", function (d) {
                return y(d.y) + padding
            });

        bar.append("text")
            .attr("x", function (d) {
                return x(d.x) + padding
            })
            .attr("y", function (d) {
                return y(d.y) + padding + 15
            })
            .attr("text-anchor", "middle")
            .text(function (d) {
                return d.y
            });

        svg.append("g")
            .attr("class", "x axis")
            .attr("transform", "translate(" + padding + "," + (height - padding) + ")")
            .call(xAxis)
            .append("text")
            .attr("class", "axisLabel")
            .attr("x", (width - 2 * padding) / 2)
            .attr("y", padding - 20)
            .style("text-anchor", "middle")
            .text("RSSI Values in dBm");

        svg.append("g")
            .attr("class", "y axis")
            .attr("transform", "translate(" + padding + "," + padding + ")")
            .call(yAxis)
            .append("text")
            .attr("transform", "rotate(-90)")
            .attr("class", "axisLabel")
            .attr("y", 0 - padding + 20)
            .attr("x", 0 - (height / 2))
            .text("Number of Beacon Packets");

    }
}

