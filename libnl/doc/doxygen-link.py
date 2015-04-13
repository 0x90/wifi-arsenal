#!/usr/bin/env python

from __future__ import print_function
import fileinput
import re
import sys


rc_script = re.compile(r'\s*(.*\S)?\s*')

def parse_dict(filename):
	links = {}
	for line in open(filename, 'r'):
		m = re.match('^([^=]+)=([^\n]+)$', line);
		if not m:
			continue
		name = m.group(1)
		value = m.group(2)

		# strip leading and trailing whitespace
		m = rc_script.match(name)
		if m:
			name = m.group(1)

		# skip special names
		if name == '':
			continue
		if name == '\\':
			continue

		links[name] = "<a href=\"" + value + "\" class=\"dg\">" + name + "</a>"
	return links

links = parse_dict(sys.argv[1])

def translate(match):
	return links[match.group(1)]

# match for all names, with word boundaries \b
rc = re.compile(r'\b(' + '|'.join(map(re.escape, sorted(links, reverse=True))) + r')\b')

for line in open(sys.argv[2], 'r'):
	print(rc.sub(translate, line), end='')
