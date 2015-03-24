#!/bin/sh

VERSION="0.3.0"
OUT="$1"

echo '#include "acs.h"' > "$OUT"

if head=`git rev-parse --verify HEAD 2>/dev/null`; then
	git update-index --refresh --unmerged > /dev/null
	descr=$(git describe)

	# on git builds check that the version number above
	# is correct...
	[ "${descr%%-*}" = "v$VERSION" ] || exit 2

	v="${descr#v}"
	if git diff-index --name-only HEAD | read dummy ; then
		v="$v"-dirty
	fi
else
	v="$VERSION"
fi

echo "const char acs_version[] = \"$v\";" >> "$OUT"
