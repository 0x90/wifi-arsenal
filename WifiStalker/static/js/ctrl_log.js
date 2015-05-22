// Author: Tomasz bla Fortuna
// License: MIT

/* Log controller */
app.controller("LogCtrl", function($scope, $http, $interval) {
    $scope.logs = [];

    $scope.loadData = function() {
        var httpRequest = $http({
            method: 'GET',
            url: '/api/logs',
            data: {}
        }).success(function(data, status) {
            $scope.logs = data.logs;
        });
    };

    // Auto refresh
    $interval($scope.loadData, 10000);
});


