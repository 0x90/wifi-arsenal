# Wifi geolocation

This is a simply python script for printing out your latitude and longitude by querying Google Maps API with the location of nearby wireless access points.  It is OSX only since it grabs your nearest access points from the Lion Airport utility (maybe a future fork can make this part cross-platform?).

Once it has wifi points, it queries Google Maps and parses out your latitude and longitude from the resulting JSON. It seems to be quite accurate, within 20 meters or so.

