#!/bin/gawk

function abs(value) {
  return(0 < value ? value : -value);
}

BEGIN{ x=0; n=0; }
{ x+=abs($1-$2); ++n; }
END{ if(0 == n) print "-"; else print x/n; }
