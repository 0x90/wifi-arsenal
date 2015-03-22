#!/bin/awk

function min(x, y) {
	 return ((x < y)? x : y);
}

BEGIN{ xmin="UNKNOWN"; }
{ t=$1; xmin=min(xmin, t); }
END{ print xmin; }
