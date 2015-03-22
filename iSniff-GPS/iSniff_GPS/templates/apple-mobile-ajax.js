{% load dict_lookup %}
{% load dot_colour %}

{% for b in bssids %}
  var myLatLng = new google.maps.LatLng{{ apdict|key:b }};
  apData.push(myLatLng);
  var marker = new google.maps.Marker({position: myLatLng, map: map, title: '{{manufdict|key:b}}', icon: {% if b == bssid %}bigRedDot{%else%}{{manufdict|key:b|dot_colour}}{%endif%}});
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

  document.getElementById('bssid').innerHTML='Cell {{bssid}}';
  document.getElementById('results').innerHTML=markersArray.length+' cells ('+{{hits}}+' added)';