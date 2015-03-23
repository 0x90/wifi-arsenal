var shell = require('shelljs')
var airport = '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/'
shell.cd(airport)


var WebSocketServer = require('ws').Server
    , wss = new WebSocketServer({port: 6587});

console.log('Websocket is opened at 6587...');

wss.on('connection', function(ws) {

    setInterval(function(){
        shell.exec('./airport -s', {async:true, silent:true}, function(code, output) {
            ws.send(output)
        });
    },4000)

});

