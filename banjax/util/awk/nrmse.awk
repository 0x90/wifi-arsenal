#!/bin/gawk

function min(x,y) {
	 return ((x < y) ? x : y);
}

function max(x,y) {
	 return ((x > y) ? x : y);
}

BEGIN{ x=0; xmin=1e400; xmax=-1e400; n=0; }
{ t=(($1-$2)**2); x+=t; xmin=min(xmin,t); xmax=max(xmax,t); n++; }
END{ if(0 == n || 0 == (xmax - xmin)) print "-"; else print (sqrt((1/n) * x) / (xmax - xmin)); }
