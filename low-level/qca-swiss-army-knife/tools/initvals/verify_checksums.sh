#!/bin/sh

CSUM_DIR=".tmp_checksum"
get_family_checksum()
{
	local family="$1"
	local suffix="$2"
	local flag

	[ "$suffix" == "hal" ] && flag="ATHEROS=1"
	[ -n "$ATH9K_DIR" ] && flag="$flag ATH9K_DIR=$ATH9K_DIR"

	make clean all $flag >/dev/null
	./initvals -f $family > "$CSUM_DIR/${family}_$suffix.txt"
	./initvals -f $family | sha1sum | sed -e 's/[ -]//g'
}

verify_family_checksum()
{
	local family="$1"
	local sum_hal
	local sum_ath9k
	local res

	sum_hal=$(get_family_checksum $family hal)
	sum_ath9k=$(get_family_checksum $family ath9k)

	[ "$sum_hal" == "$sum_ath9k" ] && res="pass" || res="fail"
	printf "%-14s %-40s %s\n" "$family" "$sum_hal" "$res"
	[ "$res" == "fail" ] && \
		diff -Nurw "$CSUM_DIR/${family}_hal.txt" "$CSUM_DIR/${family}_ath9k.txt" | grep '^+[0-9a-f]'
}

FAMILIES="$@"
[ -z "$FAMILIES" ] && FAMILIES="ar5008 ar9001 ar9002 ar9003-2p2 ar9330-1p1 ar9330-1p2 ar9340 ar9462-1p0 ar9485 ar955x-1p0 ar9565-1p0 ar9580-1p0"

mkdir -p "$CSUM_DIR"
for family in $FAMILIES; do
	verify_family_checksum $family
done
rm -rf "$CSUM_DIR"
