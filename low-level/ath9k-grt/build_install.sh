./makeall.sh
sudo rmmod ath9k.ko ath9k_common.ko ath9k_hw.ko ath.ko grt_redirect.ko;
sudo dmesg -c > /dev/null
sudo insmod grt_redirect/grt_redirect.ko;
sudo insmod ath.ko;
sudo insmod ath9k/ath9k_hw.ko;
sudo insmod ath9k/ath9k_common.ko;
sudo insmod ath9k/ath9k.ko;
dmesg | less
