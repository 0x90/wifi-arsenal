#!/bin/bash

#
# Based on a script found on the englinemtn-devel mailinglist
# written by Carsten Haitzler <ras...@rasterman.com>
#

for f in api/group__*.html
do
	bf=$(basename $f)

	grep -oE "href=\"$bf#[a-z0-9]+\">[^<]+</a>" $f |
		sed 's/href="\([^"]*\)">\([^<]*\)<\/a>/\2=api\/\1/'
done
