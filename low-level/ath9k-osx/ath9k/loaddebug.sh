#!/bin/sh
source preload

echo "file attribute adjusting for  ${FULL_PRODUCT_NAME}"

sudo kextunload -b ${MODULE_NAME}  #com.ryan.at9k

cd "${BUILT_PRODUCTS_DIR}"

sudo rm -rf /System/Library/Extensions.mkext
sudo rm -rf /System/Library/Extensions.kextcache

sudo chown -R root:wheel ${FULL_PRODUCT_NAME}
sudo find ${FULL_PRODUCT_NAME} -type d -exec chmod 0755 {} \;
sudo find ${FULL_PRODUCT_NAME} -type f -exec chmod 0644 {} \;

sudo kextutil -t "${FULL_PRODUCT_NAME}"
#sudo kextload -v "${FULL_PRODUCT_NAME}"
#sudo kextcache -k /System/Library/Extensions

sudo find ${FULL_PRODUCT_NAME} -type d -exec chmod 0777 {} \;
sudo find ${FULL_PRODUCT_NAME} -type f -exec chmod 0777 {} \;
