# kismeth2earth

kismet2earth is composed by 2 utilities written in Python and an empty Sqlite3 database. The scope of these utilities is parsing Kismet logs to get collected data from wireless networks and generate a Google Earth map that displays all networks found.

## k2db

k2db parses Kismet netxml logs extracting wireless networks informations from them and inserting these data into the database. If the wifi network is already present in the database, the content is updated. This allows add new wifi networks to the database without loosing the old one.

```
Usage: k2db.py [options]

Options:
  -h, --help            show this help message and exit
  -i FILENAME, --input=FILENAME
                        Path to netxml input file.
  -o DATABASE, --output=DATABASE
                        Path to Sqlite database file.
```

## db2ge

db2ge gets from the database alla available networks and export them in a Google Earth file. The default template uses three icons to identify networks: green = not protected wifi, orange = WEP protected wifi, red = WPA protected wifi.

```
Usage: db2ge.py [options]

Options:
  -h, --help            show this help message and exit
  -i DATABASE, --input=DATABASE
                        Path to Sqlite3 database.
  -o FILENAME, --output=FILENAME
                        Path to .kml output file.
  -w, --wpa             Export WPA encrypted networks.
  -p, --wep             Export WEP encrypted networks.
  -n, --open            Export Open networks.
  -a, --all             Export all networks.
```

## Legal Notes

Gathering wireless networks informations could not be legal in your country. This utility just manage already collected data using Kismet. It's strongly suggested not using Kismet in your country if it's not allowed and not publishing maps generated with whis software.
                    
