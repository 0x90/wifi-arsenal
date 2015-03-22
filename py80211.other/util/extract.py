#
# nl80211 enumeration extractor script
#
# Copyright 2013 Arend van Spriel <aspriel@gmail.com>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
from pycparser import parse_file, c_ast
import argparse
import subprocess
import os.path
import os
import sys
import re

EXTRACT_HEADER = 'extract.h'
hdrpath = 'include|uapi|linux|nl80211.h'.replace('|', os.sep)
srcpath = 'net|wireless|nl80211.c'.replace('|', os.sep)

args = None

def extract_prepare():
	global hdrpath, srcpath, args
	parser = argparse.ArgumentParser(description='extract code from nl80211 source files')
	parser.add_argument('srcdir', help='source tree holding nl80211 files')
	parser.add_argument('destdir', help='directory to store generated files')

	# parse command line arguments
	args = parser.parse_args()

	gitdir = os.path.join(args.srcdir, '.git')
	if not os.path.exists(os.path.join(args.srcdir, '.git')):
		sys.stderr.write('warning: could not find git revision info in source tree\n')
		git_commit = 'unknown'
	else:
		git_commit = subprocess.check_output(['git', '--git-dir=%s' % gitdir, 'log', '-1', '--oneline'])
		sys.stdout.write('source tree on commit %s\n' % git_commit)

	if not os.path.exists(os.path.join(args.srcdir, hdrpath)):
		sys.stderr.write('error: provided source tree does contain \'%s\'\n' % hdrpath)
		sys.exit(1)

	hdrpath = os.path.join(args.srcdir, hdrpath)
	ret = subprocess.call([ 'cp', hdrpath, '.' ])
	if ret != 0:
		sys.stderr.write('error: failed to copy \'%s\'\n' % hdrpath)
		sys.exit(1)

	if not os.path.exists(os.path.join(args.srcdir, srcpath)):
		sys.stderr.write('error: provided source tree does not contain \'%s\'\n' % srcpath)
		sys.exit(1)

	srcpath = os.path.join(args.srcdir, srcpath)
	ret = subprocess.call([ 'cp', srcpath, '.' ])
	if ret != 0:
		sys.stderr.write('error: failed to copy \'%s\'\n' % srcpath)
		sys.exit(1)

	return git_commit

def rmpfx(name, pfx='NL80211_'):
	n = name.lstrip('_')
	if not n.startswith(pfx):
		return name
	return n[len(pfx):]

def oper_str(oper):
	if isinstance(oper, c_ast.Constant):
		return str(oper.value)
	elif isinstance(oper, c_ast.ID):
		return rmpfx(oper.name)
	return None

def dump_binary_op(out, e, op):
	c = op.children()
	left = c[0][1]
	right = c[1][1]
	out.write('%s = %s %s %s\n' % (rmpfx(e.name), oper_str(left), op.op, oper_str(right)))

def dump_enum(out, enum):
	id = 0
	list = enum.children()[0][1]
	for dummy, e in list.children():
		if len(e.children()) == 0:
			out.write('%s = %d\n' % (rmpfx(e.name), id))
			id += 1
		elif isinstance(e.children()[0][1], (c_ast.ID, c_ast.Constant)):
			out.write('%s = %s\n' % (rmpfx(e.name), oper_str(e.children()[0][1])))
		elif isinstance(e.children()[0][1], c_ast.BinaryOp):
			dump_binary_op(out, e, e.children()[0][1])
		else:
			print e.children()[0][1]

def dump_enum2str(out, count, enum):
	list = enum.children()[0][1]
	if enum.name == None:
		out.write('unnamed%dtostr = {\n' % count)
	else:
		out.write('%s2str = {\n' % enum.name)
	for dummy, e in list.children():
		if len(e.children()) != 0:
			if not isinstance(e.children()[0][1], c_ast.BinaryOp):
				continue
			if e.children()[0][1].op != '<<':
				continue
		out.write('\t%s: "%s",\n' % (rmpfx(e.name), e.name))
	out.write('}\n')

def dump_filehdr(out, git):
	out.write('###########################################################\n')
	out.write('# This file is generated using extract.py using pycparser\n')
	out.write('###########################################################\n')
	out.write('# revision:\n')
	out.write('#\t%s' % git)
	out.write('###########################################################\n')

def generate_defs(git, ast):
	global args
	sys.stderr.write('generating python definitions\n')
	defs = open(os.path.join(args.destdir, 'defs.py'), 'w')
	dump_filehdr(defs, git)
	for ext in ast.ext:
		if isinstance(ext.type, c_ast.Enum):
			dump_enum(defs, ext.type)
	defs.close()

def generate_strmap(git, ast):
	global args
	sys.stderr.write('generating python string mappings\n')
	count = 0
	strmap = open(os.path.join(args.destdir, 'strmap.py'), 'w')
	dump_filehdr(strmap, git)
	strmap.write('from defs import *\n')
	for ext in ast.ext:
		if isinstance(ext.type, c_ast.Enum):
			dump_enum2str(strmap, count, ext.type)
			count += 1
	strmap.close()

def dump_policy_array(out, decl):
	out.write('#\n# policy: %s\n#\n' % decl.name)
	out.write('%s = nla_policy_array(' % decl.name)
	typ = type(decl.type.dim)
	if typ == c_ast.BinaryOp:
		c = decl.type.dim.children()
		left = c[0][1]
		right = c[1][1]
		out.write('%s %s %s' % (oper_str(left), decl.type.dim.op, oper_str(right)))
	elif typ == c_ast.ID:
		out.write('%s' % oper_str(decl.type.dim))
	out.write(')\n')
	for exp in decl.init.exprs:
		comma_prefix = False
		for initexp in exp.expr.exprs:
			out.write('%s[%s].%s = ' % (decl.name, oper_str(exp.name[0]), oper_str(initexp.name[0])))
			out.write('%s\n' % oper_str(initexp.expr))

def generate_policy(git):
	global args
	# we first extract all nla_policy definitions
	# from the source file and feed only those to
	# the abstract source tree parser.
	sys.stderr.write('extract policy definitions\n')
	inputdata = open('nl80211.c', 'r').read()
	policies = re.findall('(struct nla_policy[ \t\n]+[^;]+;)', inputdata, re.M)

	if not os.path.exists('tmp_nl80211.c'):
		tmpfile = open('tmp_nl80211.c', 'w')
		tmpfile.write('#include "extract.h"\n')
		for p in policies:
			tmpfile.write(p+'\n')
		tmpfile.close()
	ast = parse_file('tmp_nl80211.c', use_cpp=True)
	if ast == None:
		return

	# generate policy maps
	polmap = open(os.path.join(args.destdir, 'policy.py'), 'w')
	dump_filehdr(polmap, git)
	sys.stderr.write('create policy mappings\n')
	n = 0
	polmap.write('from netlink.capi import *\n')
	polmap.write('from defs import *\n')
	polmap.write('\n# defines used in nl80211.c\n')
	polmap.write('ETH_ALEN = 6\n')
	polmap.write('WLAN_MAX_KEY_LEN = 32\n')
	polmap.write('WLAN_PMKID_LEN = 16\n')
	polmap.write('IEEE80211_MAX_DATA_LEN = 2304\n')
	polmap.write('IEEE80211_MAX_MESH_ID_LEN = 32\n')
	polmap.write('IEEE80211_MAX_SSID_LEN = 32\n')
	polmap.write('NLA_NUL_STRING = NLA_NESTED + 2\n')
	polmap.write('NLA_BINARY = NLA_NESTED + 3\n\n')
	for ext in ast.ext:
		# filter out array declarations
		if not isinstance(ext.type, c_ast.ArrayDecl):
			continue
		# check if it is a nla_policy
		if not isinstance(ext.type.type.type, c_ast.Struct):
			continue
		if not ext.type.type.type.name == 'nla_policy':
			continue
		if not hasattr(ext, 'init'):
			# maybe need to shout here?
			continue
		dump_policy_array(polmap, ext)
	polmap.close()

###########################################################
# start of script
###########################################################
try:
	commit = extract_prepare()

	ast = parse_file(EXTRACT_HEADER, use_cpp=True)
	generate_defs(commit, ast)
	generate_strmap(commit, ast)

	generate_policy(commit)
	sys.stderr.write('Done!\n')
except SystemExit:
	sys.stderr.write('Aborting..!!\n')

