#!/bin/gawk

function abs(value) {
  return(0 < value ? value : -value);
}

{ print abs($1-$2); ++n; }
