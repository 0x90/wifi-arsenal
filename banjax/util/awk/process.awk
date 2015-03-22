/^$/ { x=""; }
{ if ($1 == "File:") x=$0; else if ($1 == "MAC:") { if(x != "") print x ", " $0; else print; } }
