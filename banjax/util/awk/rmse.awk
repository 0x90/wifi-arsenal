#!/bin/gawk

BEGIN{ x=0; n=0; }
{ x+=(($1-$2)**2); ++n; }
END{ if(0 == n) print "-"; else print sqrt((1/n) * x); }
