# Project Watcher - Maltego with a twist of wireless

This is a canari framework based Maltego transform pack that allows you to perform wireless sniffing within Maltego.
It uses a sqlite3 database to store collected data allowing for future expansion of the project and to use the data elsewhere.

It has been tested on Kali and requires the following additional software (outside of Python).

aircrack-ng

The following python modules are also required:

sqlite3
requests
canari (goes without saying)

To install the transform pack you need to do the following (make sure you have canari installed already):

1. clone this repo `git clone https://github.com/catalyst256/Watcher.git`
2. change to the `src` directory `cd src/`
3. `canari create-profile Watcher -w [full path to src folder]` on my machine this is:
            `canari create-profile Watcher -w /root/localTransforms/Watcher/src`
4. Load Maltego and import configuration file that was just created in the `src` folder.

You will have a number of new transforms, entities and a Maltego machine to use.

To use Watcher the process is as follows:

1. Create an interface entity in Maltego (set to your wireless interface name)
2. Run the `Watcher - Set Interface into Monitor Mode`
3. Run the `Watcher - Create database` (this creates a sqlite database in the `src/Watcher/resource/database` folder)
4. Run the `Watcher - Sniff wireless sniff` transform (leave this running)
5. Run the Maltego Machine `Watcher - Hunter` (accessible from the monitor interface entity)

Leave it running to see all the beacon and probe requests from devices flow into a beautiful graph..

Enjoy!! (any issues raise a ticket on GitHub)
