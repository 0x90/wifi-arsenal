WiFi Lookup
==================
ROS based WiFi location code developed for the Building Wide Intelligence Project at The University of Texas. This branch is for a catkin specific version of the code, made for integration with ros hydro.

Overview
--------

This package consists of three parts to accomplish localization. They include:
- WiFi_Data: Get dB and MAC addresses for all visible WiFi access points with the ESSID provided as a parameter.
- WiFi_Listener: Takes the data from WiFi data and saves using serialization in a Data Structure for lookup later.
- WiFi_Publisher: Reads data serialized from the Listener and publishes it in (X,Y) coords based off the origin provided as a parameter.

This package has no external ROS package dependencies.

Usage instructions
------------------

###wifi_data
The wifi_data requires the presence of the UNIX command "iwlist". If not present, install it with:
```
  sudo apt-get install wireless-tools
```

To run this node, run the following command
```
  rosrun wifi_lookup wifi_data
```
It will then being broadcasting a topic named "wifi_data" which holds a custom data type, containing an array of access point ESSIDs (MAC), and their respective decibel levels (dB). Additionally, the topic has a "length", which stores the size of the array.

###wifi_listener
This node requires that wifi_data be running.

To run this node, run the following command
```
  rosrun wifi_lookup wifi_listener <x> <y>
```
where x and y are the current coordinates of the robot's location. 

To save the data at this point, the node must be killed. This serializes the constructed data tables and stores the data seen to the point passed as a parameter. Simply run this node with the correct parameters, wait a second to gather data at the point, and kill the node. This process must be repeated at each location.

###wifi_publisher (Not Working: Unfinished)
This node requires that wifi_data be running, and a map has been built from wifi_listener

To run this node, run the following command
```
  rosrun wifi_lookup wifi_publisher <map_file>
```
where map file is the location of the .pk file created by wifi_listener.

Once running, this node will publish an array point messages. The array's first index will contain the point at which the node believes the robot most likely located, which each subsequent point decreasing in probability.


Additional Information
----------------------

This node was created by [Robert Lynch](https://github.com/BobertForever) and [Josh Eversmann](https://github.com/jeversmann) for the Freshman Research Initative at the University of Texas in the Spring of 2013.

For more information on the project, check the Building Wide Intelligence wiki (a user and password is required):
[BWI Wiki](http://farnsworth.csres.utexas.edu/bwi/index.php/CS378/WiFi_Localization)
