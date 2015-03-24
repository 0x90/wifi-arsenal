#!/usr/bin/env python

import sys
try:
       from M2Crypto import RSA
except ImportError, e:
       sys.stderr.write('ERROR: Failed to import the "M2Crypto" module: %s\n' % e.message)
       sys.stderr.write('Please install the "M2Crypto" Python module.\n')
       sys.stderr.write('On Debian GNU/Linux the package is called "python-m2crypto".\n')
       sys.exit(1)

def print_ssl_64(output, name, val):
    while val[0] == '\0':
        val = val[1:]
    while len(val) % 8:
        val = '\0' + val
    vnew = []
    while len(val):
        vnew.append((val[0], val[1], val[2], val[3], val[4], val[5], val[6], val[7]))
        val = val[8:]
    vnew.reverse()
    output.write('static BN_ULONG %s[%d] = {\n' % (name, len(vnew)))
    idx = 0
    for v1, v2, v3, v4, v5, v6, v7, v8 in vnew:
        if not idx:
            output.write('\t')
        output.write('0x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x, ' % (ord(v1), ord(v2), ord(v3), ord(v4), ord(v5), ord(v6), ord(v7), ord(v8)))
        idx += 1
        if idx == 2:
            idx = 0
            output.write('\n')
    if idx:
        output.write('\n')
    output.write('};\n\n')

def print_ssl_32(output, name, val):
    while val[0] == '\0':
        val = val[1:]
    while len(val) % 4:
        val = '\0' + val
    vnew = []
    while len(val):
        vnew.append((val[0], val[1], val[2], val[3], ))
        val = val[4:]
    vnew.reverse()
    output.write('static BN_ULONG %s[%d] = {\n' % (name, len(vnew)))
    idx = 0
    for v1, v2, v3, v4 in vnew:
        if not idx:
            output.write('\t')
        output.write('0x%.2x%.2x%.2x%.2x, ' % (ord(v1), ord(v2), ord(v3), ord(v4)))
        idx += 1
        if idx == 4:
            idx = 0
            output.write('\n')
    if idx:
        output.write('\n')
    output.write('};\n\n')

def print_ssl(output, name, val):
    import struct
    output.write('#include <stdint.h>\n')
    if len(struct.pack('@L', 0)) == 8:
        return print_ssl_64(output, name, val)
    else:
        return print_ssl_32(output, name, val)

def print_ssl_keys(output, n):
    output.write(r'''
struct pubkey {
	struct bignum_st e, n;
};

#define KEY(data) {				\
	.d = data,				\
	.top = sizeof(data)/sizeof(data[0]),	\
}

#define KEYS(e,n)	{ KEY(e), KEY(n), }

static struct pubkey keys[] = {
''')
    for n in xrange(n + 1):
        output.write('	KEYS(e_%d, n_%d),\n' % (n, n))
    output.write('};\n')
    pass

def print_gcrypt(output, name, val):
    output.write('#include <stdint.h>\n')
    while val[0] == '\0':
        val = val[1:]
    output.write('static const uint8_t %s[%d] = {\n' % (name, len(val)))
    idx = 0
    for v in val:
        if not idx:
            output.write('\t')
        output.write('0x%.2x, ' % ord(v))
        idx += 1
        if idx == 8:
            idx = 0
            output.write('\n')
    if idx:
        output.write('\n')
    output.write('};\n\n')

def print_gcrypt_keys(output, n):
    output.write(r'''
struct key_params {
	const uint8_t *e, *n;
	uint32_t len_e, len_n;
};

#define KEYS(_e, _n) {			\
	.e = _e, .len_e = sizeof(_e),	\
	.n = _n, .len_n = sizeof(_n),	\
}

static const struct key_params keys[] = {
''')
    for n in xrange(n + 1):
        output.write('	KEYS(e_%d, n_%d),\n' % (n, n))
    output.write('};\n')
    

modes = {
    '--ssl': (print_ssl, print_ssl_keys),
    '--gcrypt': (print_gcrypt, print_gcrypt_keys),
}

try:
    mode = sys.argv[1]
    files = sys.argv[2:-1]
    outfile = sys.argv[-1]
except IndexError:
    mode = None

if not mode in modes:
    print 'Usage: %s [%s] input-file... output-file' % (sys.argv[0], '|'.join(modes.keys()))
    sys.exit(2)

output = open(outfile, 'w')

# load key
idx = 0
for f in files:
    try:
        key = RSA.load_pub_key(f)
    except RSA.RSAError:
        key = RSA.load_key(f)

    modes[mode][0](output, 'e_%d' % idx, key.e[4:])
    modes[mode][0](output, 'n_%d' % idx, key.n[4:])
    idx += 1

modes[mode][1](output, idx - 1)
