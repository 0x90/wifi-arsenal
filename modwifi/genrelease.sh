#!/bin/bash
set -e

echo -e "Make sure all projects are on the correct branch...\n"

# Let at modules generate their result in a tar
cd ../ath9k-htc/ && ./build.sh release && cd -
cd ../backports/ && ./release.sh       && cd -
cd ../tools/     && make release       && cd -

# Combine and zip all results
cp ../drivers.tar modwifi.tar
tar --concatenate --file=modwifi.tar ../firmware.tar
tar --concatenate --file=modwifi.tar ../tools.tar
gzip modwifi.tar

