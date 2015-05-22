# Wireless Config
A 802.1x configuration suite for Mac OS X
Currently This suite is in testing

## Contributing code

#### Fork the repository to your github account
[Click the little button in the corner](https://help.github.com/articles/fork-a-repo#step-1-fork-the-spoon-knife-repository)

#### Clone your fork of the tool and add remotes
1. Clone your fork of the repo
`git clone https://yourusername@github.com/yourusername/WirelessConfig.git`  

example output:
~~~
Cloning into WirelessConfig...
Password:
remote: Counting objects: 361, done.
remote: Compressing objects: 100% (188/188), done.
remote: Total 361 (delta 159), reused 348 (delta 146)
Receiving objects: 100% (361/361), 5.49 MiB | 861 KiB/s, done.
Resolving deltas: 100% (159/159), done.
~~~

2. Add the upstream remote for the main repo (mine)
`cd WirelessConfig`  
`git remote add upstream https://github.com/acidprime/WirelessConfig.git`  

3. Do not make changes until you create a new branch below

#### Make a new branch with your changes

1. Pull any recent updates to the master branch on the upstream repo.
`cd WirelessConfig`  
`git pull upstream master`  

2. Create a new feature branch
`cd WirelessConfig`  
`git checkout -b my_new_feature`  

3. Make your changes to a file in the repo
`cd WirelessConfig`  
`vim wifiutil.py`  
`:%s/lookatme/makingchanges/g`  
`:w`  
`:!git commit % -m "Now I know how to make commits inside vim"`  
`:%s/lookatme/makingmorechangessothecommitworksbelow/g`  
`:x`  

4. Commit your changes
`cd WirelessConfig`  
`git commit wifiutil.py -m  "Now I know how to make commits from the command line"`  

5. Replay any changes made to the upstream fork since you started  
`git checkout master`  
`git pull upstream master`  
`git checkout my_new_feature`  
`git rebase origin master`  
`open http://goo.gl/a7QYUI`  

6. Push the changes in your branch back to your fork  
`git push origin my_new_feature`  

7. Head over to github and send a pull request

[Sending a Pull request](https://help.github.com/articles/using-pull-requests#initiating-the-pull-request)  

## Usage

`wifiutil.py`
Is a 10.5,10.6,10.7,10.8 Wireless configuration command line tool

example usage:
```shell
sudo ./wifiutil.py --username=bob --password=f00b4r --plist='/path/to/wifiutil.settings.plist'
```
or debug:
```shell
sudo ./wifiutil.py --username=bob --password=f00b4r --plist='/path/to/wifiutil.settings.plist' -d
```

This script has support for removal and addtion of WPA2E networks.
Technically it has support for WPA too but this only works really well on 10.6+

##WirelessConfig.bundle:
A Casper self service plugin, see this document for scoped installation:

https://jamfnation.jamfsoftware.com/article.html?id=177

Otherwise you can upload through the JSS portal but not recommended while this in Beta.

`kcutil`:
A keychain binary because 10.5 is stupid and I hate it, please upgrade.

wifiutil.settings.plist:
Two arrays, to add and remove networks
Note this is excluded from the build process, check the downloads section for examples
This file MUST BE EDITED for your env settings. Its in the .bundle, so right click
and "Show Package Contents" from there its ./Contents/Resources/wifiutil.settings.plist


To Do:
* Currently the script requires trusted Certificates be configured through
some other process. This will eventually be embeded in a future release.

* This is currently PEAP centric (plist key 25) but needs further testing with other
parameters ,including multiple authentication options.

* Need to get the protocol declaration right so Xcode stops complaining

* networksetup may prompt for password on 10.7, some rootObject auth deal

* Figure out why I am having to rely so heavly on bindings and properties for ui changes:


http://stackoverflow.com/questions/9639370/counting-the-length-of-two-nstextfields-not-working

Both issues are already worked around but I'm curious why this is this way

* Modify the code to pass the ENV vars to the command as parameters is not as secure.

Beta Notes:

Please Make sure to modify your wifiutil.settings.plist with new guids, here is an example of how to generate them
```shell
sand-bender:~ acid$ uuidgen | tr '[:upper:]' '[:lower:]'
36afb32f-ee45-46e1-9aa8-8a58d013acad
sand-bender:~ acid$ uuidgen | tr '[:upper:]' '[:lower:]'
3ca519d7-98f2-4f50-b0d2-370473b71985
```
  
```shell
sand-bender:~ acid$ uuidgen
8A1E81A7-170B-466C-B2B2-BF8209AFF994
sand-bender:~ acid$ uuidgen
84E74439-A169-423B-A509-59EC1A0A2679
```
These are used for the profile thats created and the keychain items so they should be unique.

Please look through ALL the keys, I will upload a key value guide in the future, but for the moment

please just find and replace SSID and org name, other keys are written directly to plist so modify

with caution. Example is setup for PEAP (key 25) and a ssid called "newNetwork"

Note that newNetwork is listed in the remove and the add, so that password changes can happen

