export CROSS_COMPILE=~/android/system/prebuilt/linux-x86/toolchain/arm-eabi-4.4.3/bin/arm-eabi-
export ARCH=arm
export USE_SEC_FIPS_MODE=true
cd ~/android/system/kernel/samsung/smdk4210
make modules SUBDIRS=drivers/net/wireless/bcmdhd