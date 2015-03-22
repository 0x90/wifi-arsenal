// Author: Tomasz bla Fortuna
// License: MIT

app.directive('wifiChart', function() {
    return {
        restrict: 'A',
        scope: {
            chartData: '='
        },
        //template: '<canvas width="800" height="400"></canvas>',
        link: function(scope, element, attrs) {
            scope.canvas = element[0];
            scope.context = scope.canvas.getContext('2d');

            Chart.defaults.global.animation = false;

            function update(newValue) {
                var options = {
                    bezierCurve: false,
                    datasetFill : false
                };
                if (newValue == null) {
                    return;
                }
                var chart = new Chart(scope.context).Line(newValue, options);
            }
            scope.$watch('chartData', update);
        }
    };
});


app.controller("ChartsCtrl", function($scope, $http, $interval, $log) {
    /*
     * Inherited:
     * $scope.tab - this tab
     */
    $scope.mac = $scope.tab.id;
    $scope.timeWindow = 24*60*60;
    $scope.chartData = undefined;
    $scope.refreshing = false;

    /*
     * Helper functions
     */
    $scope.refreshChart = function() {
        $scope.refreshing = true;

        function setChartData(data) {
            $scope.refreshing = false;
            $scope.chartData = data.chart;
        }

        function error() {
            $scope.refreshing = false;
        }

        // Get chart data
        $http({
            method: 'GET',
            url: '/api/graph/strength/' + $scope.mac + '/' + $scope.timeWindow,
            data: {}
        }).success(setChartData).error(error);
    };

    /* Initialize tab contents */
    $scope.refreshChart();
});

