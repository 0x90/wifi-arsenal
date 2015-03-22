#!/bin/awk

BEGIN{ x=0; y=0; n=0; }
{ x+=$1; y+=(($1-$2)**2); ++n; }
END{ if(0 == n) print "-"; else print ((sqrt((1/n) * y) / (x/n)) * 100); }
