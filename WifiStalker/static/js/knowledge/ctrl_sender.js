// Author: Tomasz bla Fortuna
// License: MIT

app.filter('orderByPackets', function() {
    return function(input, attr) {
        console.log('called with', input, attr);
        if (!angular.isObject(input))
            return input;

        /* Create an array */
        var array = [];
        for (var key in input) {
            array.push((key, input[key]));
        }

        /* Sort it */
        array.sort(function(a, b) {
            a = a[attr];
            b = b[attr];
            return a - b;
        });
        return array;
    };
});


app.controller("SenderCtrl", function($scope, $http, $interval, $log) {
    /*
     * Inherited:
     * $scope.tab - this tab
     */
    $scope.mac = $scope.tab.id;
    $scope.sender = undefined;
    $scope.related = undefined;
    $scope.refreshing = false;

    /*
     * Helper functions
     */
    $scope.refreshSender = function() {
        function setSenderData(knowledge, related) {
            $scope.refreshing = false;
            $scope.sender = knowledge[0];
            $scope.related = related;

            /* Update tabs names */
            $scope.renameTabs($scope.mac, $scope.sender.user.alias);
        }

        function error() {
            $scope.refreshing = false;
        }

        // Get knowledge
        $scope.refreshing = true;
        $scope.loadKnowledge({
            'mac': $scope.mac,
            'success': setSenderData,
            'error': error
        });
    };

    /* Initialize tab contents */
    $scope.refreshSender();

    /*
     * Callers / main functions
     */
    $scope.saveTab = function(tab) {
        function success(data) {
            if (data['OK'] != true)
                return;

            $scope.renameTabs($scope.mac, $scope.sender.user.alias);
        }

        $http.post('/api/userdata', {
            'mac': $scope.sender.mac,
            'alias': $scope.sender.user.alias,
            'owner': $scope.sender.user.owner,
            'notes': $scope.sender.user.notes
        }).success(success);


        $scope.loadKnowledge();
    };
});
