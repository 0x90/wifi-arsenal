#!/bin/awk

function abs(value)
{
  return (value<0?-value:value);
}

BEGIN{ x=0; y=0; n=0; }
{ x+=abs($1-$2); y+=$1; ++n; }
END{ print 100 * (x / y); }
