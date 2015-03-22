// Author: Tomasz bla Fortuna
// License: MIT

/*
 * Handle data for knowledge view, has two children controllers - table and sender.
 */
app.controller("KnowledgeCtrl", function($scope, $http, $log) {
    /* Opened senders tab */
    $scope.detailsTabs = [];
    $scope.load_fail = false;

    $scope.loadKnowledge = function(opts) {
        /* Generic data loading function shared between child controllers */
        var args = {
            sort: '-aggregate.last_seen',
            mac: null,
            time_window: null,
            success: null,
            error: null
        };

        angular.extend(args, opts);

        function handle_success(data, status) {
            $scope.load_fail = false;

            if (args.success)
                args.success(data.knowledge, data.related);
        }

        function handle_error() {
            $scope.load_fail = true;
            
            if (args.error)
                args.error();
        }

        var httpRequest = $http({
            method: 'GET',
            url: '/api/knowledge',
            params: {
                time_window: args.time_window,
                sort: args.sort,
                mac: args.mac
            }
        }).success(handle_success).error(handle_error);
    };

    /* Open tab for specified sender */
    $scope.openTab = function(id, title, type, meta) {
        /* Check if already open */

        /* Try opening existing tab instead of opening new one*/
        var tab;
        for (var i in $scope.detailsTabs) {
            tab = $scope.detailsTabs[i];
            if (tab.id == id && tab.type == type) {
                // Just open it.
                tab.active = true;
                return;
            }
        }

        if (!title) {
            title = id;
        }

        /* Not opened - Open new */
        tab = {    // aa:bb:cc:dd:ee:ff
            'id': id,
            'title': title,
            'active': true,
            'type': type,

            /* Used to show icon, or contains basic tab init info (eg. mac address) */
            'meta': meta
        };
        $scope.detailsTabs.push(tab);
    };

    $scope.renameTabs = function(id, title) {
        /* Handle tab rename - during alias change. Sender might 
         * not be in local knowledge currently */

        if (!title) {
            title = id;
        }

        angular.forEach($scope.detailsTabs, function(tab) {
            if (tab.id == id) {
                tab.title = title;
            }
        });
    };

    $scope.closeTab = function(index) {
        var tabs = $scope.detailsTabs;
        tabs.splice(index, 1);
    };
});
