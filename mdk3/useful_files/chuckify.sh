#! /bin/bash

cd ..
find . -type f -exec sed -i 's/osdep/texasranger/g' {} \;
find . -type f -exec sed -i 's/mdk3/airchucknorris-ng/g' {} \;
find . -type f -exec sed -i 's/mdk2/airchucknorris-ng/g' {} \;
find . -type f -exec sed -i 's/mdk/airchucknorris/g' {} \;
find . -type f -exec sed -i 's/MDK/airchucknorris-ng/g' {} \;
mv osdep/ texasranger
mv mdk3.c airchucknorris-ng.c
cd texasranger
mv osdep.c texasranger.c
mv osdep.h texasranger.h

echo "Have a lot of fun with airchucknorris-ng..."
