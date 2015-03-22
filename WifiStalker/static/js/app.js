
/* Create application */
var app = angular.module('wifiStalker', ['ngRoute', 'ui.bootstrap']);

/* Routing configuration */
app.config(function($routeProvider, $locationProvider) {
    $routeProvider
        .when('/', {
            templateUrl: 'templates/knowledge.html'
        })
        .when('/map', {
            templateUrl: 'templates/map.html',
            controller: 'MapCtrl'
        })
        .otherwise({
            redirectTo: '/'
        });
});


/* Main controller. */
app.controller('MainCtrl', function($scope, $window, $location) {

  /* Required to update navigation bar */
  $scope.$location = $location;

});



// Examples
/*
app.factory('notify', [function() {
    var msgs = [];
    return function(msg) {
        // Does it nee to be a function?
        window.alert(msg);
    };
}]);

app.run(function($rootScope, $timeout, $log) {
    $log.info('App is running');
});
*/