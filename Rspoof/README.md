### RSPOOF

Written in python, provides an automated menu for quickly setting up the perfect fake hotspot with only a single Wifi card. The user enters a nearby 'target' acess point, and rspoof attempts to get all the clients on that network to instead connect to our fake hotspot which uses SSL stripping to get data. Also comes with dnspoof, and built in fake "router" template login pages to trick the user into supplying their login details (which is likely to be the same for their wifi).


1. Deauths all Wifi clients connected to the target.
2. Starts a fake access point while the client is deauthenticated with the same name as the target access point in order to fool the target into connecting to ours instead.
3. Once connected, dnspoof redirects all their traffic through us, and then procies it to the outside internet transparently decrypting the data in between. Optional BeeF XSS could be then injected into the targets pages in transport.
