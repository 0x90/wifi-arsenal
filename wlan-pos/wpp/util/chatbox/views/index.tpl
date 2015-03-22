<html>
        <head>
                <style>
                        body{
                                background: #fff;
                                color:#ccc;
                        }
                        h1{
                                color: #0cf;
                        }
                        input {
                                transition: all 0.50s ease-in-out;
                                -webkit-transition: all 0.50s ease-in-out;
                                -moz-transition: all 0.50s ease-in-out;
                                border: #35a5e5 1px solid;
                                border-radius: 4px;
                                outline: none;
                        }
                        input:focus {
                                box-shadow: 0 0 5px rgba(81, 203, 238, 3);
                                -webkit-box-shadow: 0 0 5px rgba(81, 203, 238, 3);
                                -moz-box-shadow: 0 0 5px rgba(81, 203, 238, 3);
                        }
                        #author{
                                padding:10px 0px;
                                font-size: 14px;
                                width:550px;
                                text-align: left;
                        }
                        #content{
                                padding-left:5px;
                                font-size:12px;
                                color:#666;
                        }
                </style>
                <script src="/chatbox/static/jquery.min.js"></script>
                <script>
                        function poll(){
                                $.ajax({
                                        type:'POST',
                                        url:'/chatbox/poll',
                                        async:true,
                                        cache:false,
                                        timeout:100000,
                                        success:function (data){
                                                offset = parseInt(data.offset);
                                                $.each(data.data,function (i,v){
                                                        $('#content').prepend('<div>'+v+'</div>');
                                                });
                                                setTimeout(poll,50);
                                        },
                                        error:function (req,sta,er){
                                                setTimeout(poll,3000);
                                        },
                                });
                        }
                        $(document).ready(function(){
                                var event = {
                                        do_send:function (){
                                                if(''==$('#input').val()){
                                                        return;
                                                }
                                                $.post('/chatbox/put',{'message':$('#input').val()},function (d){
                                                        if(d == 'OK'){
                                                                $('#input').val('');
                                                        }
                                                });
                                        },
                                };
                                $('#send').click(function (){
                                        event.do_send();
                                });
                                $('#input').keypress(function (e){
                                        if(13 == e.keyCode){
                                                event.do_send();
                                        }
                                });
                                setTimeout(poll,500);
                        });
                </script>
        </head>
        <h1>ChatBox</h1>
        <div id="author">version 0.1beta (supports all NON-IE browsers: firefox/chrome/safari/opera)</div>
        <input id="input" type="text" size="80" />
        <input id="send"  type="button" value="Send message" />
        <br>
        <br>
        
        <div id="content">
                {% for msg in messages|reverse %}
                <div>{{msg}}</div>
                {% endfor %}
        </div>
</html>
