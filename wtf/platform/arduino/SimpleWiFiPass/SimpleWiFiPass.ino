/* Copyright (c) 2014 cozybit, Inc. */

#include <WiFi.h>
// WiFiClass WiFi; // until we extern it from WiFi.h

char ssid[] = "wtf-arduino-pass-ap";     // the name of your network
char pass[] = "thisisasecret";
int status = WL_IDLE_STATUS;     // the Wifi radio's status

void setup() {
  //Initialize serial and wait for port to open:
  Serial.begin(9600);
  while (!Serial) {
    ; // wait for serial port to connect. Needed for Leonardo only
  }

  // check for the presence of the shield:
  if (WiFi.status() == WL_NO_SHIELD) {
    Serial.println("WiFi shield not present");
    // don't continue:
    while(true);
  }

 // attempt to connect to Wifi network:
  while ( status != WL_CONNECTED) {
    Serial.print("Attempting to connect to password protected SSID: ");
    Serial.println(ssid);
    status = WiFi.begin(ssid, pass);

    // wait 10 seconds for connection:
    delay(10000);
  }

  // you're connected now, so print out the data:
  Serial.print("You're connected to the password protected network");
}

void loop() {
  // check the network connection once every 10 seconds:
  WiFi.printIP();
  delay(10000);
}
