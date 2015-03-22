#!/usr/bin/gawk

function min(x,y) {
	 return ((x < y) ? x : y);
}

function max(x,y) {
	 return ((x > y) ? x : y);
}

BEGIN{ x=0; xmin=1e400; xmax=-1e400; }
{ x += $1; v[NR] = $1; xmin=min(xmin, $1); xmax=max(xmax, $1); }
END { mean = x / NR; for(i = 1; i <= NR; i++) { sumsq += (v[i] - mean) ** 2; }; print mean, sqrt(sumsq / NR), xmin, xmax; }
