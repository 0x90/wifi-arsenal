// Author: Tomasz bla Fortuna
// License: MIT

app.controller("TableCtrl", function($scope, $http, $interval, $log) {
    /*
     * Data model
     */

    /* Parameters */
    $scope.timeWindow = 120;
    $scope.refreshInterval = 10;
    $scope.refreshing = false;

    $scope.snapshotName = '';

    $scope.knowledge = null;
    $scope.sort = '-meta.running_str';

    var refreshPromise = null;

    var debug_open = false; /* Turn true to disable */

    /*
     * Callers / main functions
     */
    $scope.refreshTable = function() {
        function handle_success(knowledge, related) {
            $scope.refreshing = false;
            $scope.knowledge = knowledge;

            /* DEBUG OPEN ALL */
            if (debug_open == false) {
                debug_open = true;
                var sender = knowledge[0];
                var mac = sender.mac;
                $scope.openTab(mac, sender.user.alias, 'sender',  {ap: sender.meta.ap});
                $scope.openTab(mac, sender.user.alias, 'charts',  {ap: sender.meta.ap});
                $scope.openTab(mac, sender.user.alias, 'graphs',  {ap: sender.meta.ap});
            }
        }

        function error() {
            $scope.refreshing = false;
        }

        $scope.refreshing = true;
        $scope.loadKnowledge({
            'time_window': $scope.timeWindow,
            'sort': $scope.sort,
            'success': handle_success,
            'error': error
        });
    };

    // Initial load
    $scope.refreshTable();

    // Auto refresh
    $scope.$watch('refreshInterval', function (newVal, oldVal) {
        /* Cancel current promise */
        if (refreshPromise == null || newVal != oldVal) {
            $interval.cancel(refreshPromise);

            if ($scope.refreshInterval != 'pause')
                refreshPromise = $interval($scope.refreshTable, $scope.refreshInterval * 1000);
        }
    });

    /* Handle knowledgedumps */
    $scope.snapshotCreate = function() {
        $http.post('/snapshot', {
            'name': $scope.snapshotName,
            'timeWindow': $scope.timeWindow
        });
    };
});


