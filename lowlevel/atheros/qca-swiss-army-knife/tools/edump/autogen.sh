#!/bin/sh

echo "Running autoreconf..."

autoreconf -f -i -v
if [ $? -ne 0 ]; then
  echo "autoreconf failed"
fi
