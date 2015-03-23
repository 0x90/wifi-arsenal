var str = '';
$(function(){
    var ws = new WebSocket('ws://localhost:6587');
    ws.onmessage = function (event) {
        str = '<p>' + event.data + '</p>'
//        $('#content').html(str);
        console.log(event.data)
    };
})