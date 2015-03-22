<html>
<head>
<script>
//request part goes here.  This is an example

//response = { 'AP1':{'lts': None, 'ssidList': [], 'fts': 1376162940.327379, 'name': 'accessPoint', 'bssid': 'test', 'encryption': None, 'connectedClients': [], 'oui': None, 'auth': None, 'cipher': None, 'essid': None, 'hidden': False, 'bcast': False, 'channel': None}}

//check for shit every 2 seconds
xhr_loop()
//setInterval("xhr_loop()",200000000)

function xhr_loop(){
	if (window.XMLHttpRequest){
		xmlhttp = new XMLHttpRequest();
	}

	xmlhttp.onreadystatechange=function(){
		if (xmlhttp.readyState==4 && xmlhttp.status==200){
			response = JSON.parse(xmlhttp.responseText)
			display(response)
		}
	}
	xmlhttp.open("GET","http://127.0.0.1:8080/",true)
	xmlhttp.send()
}

function display(response){
	returned_objects_array = Object.keys(response)
	for (var i=0;i<returned_objects_array.length;i++){
	    key = returned_objects_array[i]
            value_names = Object.keys(response[key])

            //Papa Div
            mydiv = create_div(key,response[key]['name'],key)

            for (var z=0; z<value_names.length;z++){
                value_name = value_names[z]
                value = response[key][value_names[z]]
                console.log(value_name+':'+value) 
                //baby div
                
                append_element(mydiv,key+value_name,value_name,value_name+':'+value)

            }
	}
}

function type(obj){
    return Object.prototype.toString.call(obj).slice(8, -1);
}

function recurse_display(raw_json){
    keys = Object.keys(raw_json)
    for (var i=0;i<keys.length;i++){
        key = keys[i]
        if (type(raw_json[key]) == "Array"){
            list = raw_json[key]
            for (var x=0;x<list.length;x++){
                result = recurse_display(list[x])
            }
        else{
            for (var z=0; z<value_names.length;z++){
                value_name = value_names[z]
                value = response[key][value_names[z]]
                console.log(value_name+':'+value) 
                //baby div        
                append_element(mydiv,key+value_name,value_name,value_name+':'+value)

        }
    }
}

function append_element(parent_div,divid,divclass,html){
    newdiv = document.createElement("div")
    newdiv.id = divid
    newdiv.className = divclass
    newdiv.innerHTML = html
    parent_div.appendChild(newdiv)
}

//Appends a new div to the main content div
function create_div(thename,divclass,html){
    newdiv = document.createElement("div")
    newdiv.id = thename
    newdiv.className = divclass
    newdiv.innerHTML = html
    document.getElementById("content").appendChild(newdiv)
    return newdiv
}

</script>
<link rel='stylesheet' type='text/css' href='css.css'/>
</head>
<body>
	<div id="content"></div>
</body>
</html>
