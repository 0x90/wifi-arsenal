{% load dict_lookup %}

{% for b in bssids %}
  var myLatLng = new google.maps.LatLng{{ apdict|key:b }};
  apData.push(myLatLng);
  var marker = new google.maps.Marker({position: myLatLng, map: map, title: '{{b}} - {{manufdict|key:b}}', icon: {% if b == bssid %}redDot{%else%}blueDot{%endif%}});
  google.maps.event.addListener(marker, "click", function() {loadAjax("{{b}}")});
  markersArray.push(marker);
{% endfor %}

  pointArray = new google.maps.MVCArray(apData);

  if (heatmap.getMap())
  {
    heatmap.setMap(null);
    heatmap = new google.maps.visualization.HeatmapLayer({data: pointArray});
    heatmap.setMap(map);
  }

  document.getElementById('bssid').innerHTML='BSSID {{bssid}}';
  document.getElementById('results').innerHTML=markersArray.length+' APs ('+{{hits}}+' added)';