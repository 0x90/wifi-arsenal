var t = L.tileLayer("http://{s}.mqcdn.com/tiles/1.0.0/osm/{z}/{x}/{y}.jpeg", 
{subdomains:["otile1","otile2","otile3","otile4"],
attribution:"Tile Data from <a href='http://www.openstreetmap.org/' target='_blank'>OSM</a>, Tiles Courtesy of <a href='http://www.mapquest.com/' target='_blank'>MapQuest</a> <img src='http://developer.mapquest.com/content/osm/mq_logo.png'>"});
 $( "#tabs" ).tabs({
        collapsible: true,
            selected: -1
    	});

var m = L.map('map', {
    center: [42.151187,-70.949707],
    zoom: 8
}).addLayer(t);
var j = L.geoJson().addTo(m);
var g = L.geoJson().addTo(m);

$("#mac").submit(gmac)

function gmac(){
var val = $("#gm").val();
$.get('_view/MAC?key="'+val+'"',doStuff,"JSONP")
return false;
}
function doStuff(d){
j.addData(d.rows[0].value.geometry);
m.setView([d.rows[0].value.geometry.coordinates[1],d.rows[0].value.geometry.coordinates[0]],18);
}
$("#resetMAC").click(rmac)

function rmac(){
j.clearLayers();
m.setView([42.151187,-70.949707],8);
}
