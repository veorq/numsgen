#!/usr/bin/env python
"""
Generator of "nothing-up-my-sleeve" (NUMS) constants.

This aims to demonstrate that NUMS-looking constants shouldn't be
blindly trusted.

This program may be used to bruteforce the design of a malicious cipher,
to create somewhat rigid curves, etc.  As it is, it generates about
500,000 constants, and is easily tweaked to generate many more.

The code below is pretty much self-explanatory. Please report bugs.

Copyright (c) 2015 Jean-Philippe Aumasson <jeanphilippe.aumasson@gmail.com>
Under CC0 license <http://creativecommons.org/publicdomain/zero/1.0/>
"""

from base64 import b64encode
from itertools import product
from struct import unpack
from Crypto.Hash import HMAC, MD5, SHA, SHA256, SHA512
from Crypto.Protocol.KDF import PBKDF2
import mpmath as mp
import sys


# add your own special primes
PRIMES = (2, 3, 5, 7, 11, 13)

PRECISIONS = (
    42, 50, 100, 200, 500, 1000,
    16, 32, 64, 128, 256, 512, 1024,
)

# set mpmath precision
mp.mp.dps = max(PRECISIONS)

# some popular to-irrational transforms (beware exceptions)
TRANSFORMS = (
    mp.ln, mp.log10,
    mp.sqrt, mp.cbrt,
    mp.cos, mp.sin, mp.tan,
)

SEEDS = []
for prime in PRIMES:
    for transform in TRANSFORMS:
        seed = mp.nstr(abs(transform(prime)), mp.mp.dps).replace('.', '')
        for precision in PRECISIONS:
            SEEDS.append(seed[:precision])

IRRATIONALS = (
    mp.nstr(mp.phi, mp.mp.dps).replace('.', ''),
    mp.nstr(mp.pi, mp.mp.dps).replace('.', ''),
    mp.nstr(mp.e, mp.mp.dps).replace('.', ''),
)

for irrational in IRRATIONALS:
    for precision in PRECISIONS:
        SEEDS.append(irrational[:precision])


# some common encodings
def int10_ascii(x):
    return x

def hex_ascii_lo(x):
    xhex = '%x' % int(x)
    if len(xhex) % 2:
        xhex = '0' + xhex
    return xhex

def hex_ascii_hi(x):
    xhex = '%X' % int(x)
    if len(xhex) % 2:
        xhex = '0' + xhex
    return xhex

def hex_raw(x):
    return hex_ascii_lo(x).decode('hex')

def base64_from_int(x):
    return b64encode(x)

def base64_from_raw(x):
    return b64encode(hex_raw(x))

ENCODINGS = (
    int10_ascii,
    hex_ascii_lo,
    hex_ascii_hi,
    hex_raw,
    base64_from_int,
    base64_from_raw,
)


def do_hash(x, ahash):
    h = ahash.new()
    h.update(x)
    return h.digest()

def do_hmac(x, key, ahash):
    h = HMAC.new(key, digestmod=ahash)
    h.update(x)
    return h.digest()

HASHINGS = [
    lambda x: do_hash(x, MD5),
    lambda x: do_hash(x, SHA),
    lambda x: do_hash(x, SHA256),
    lambda x: do_hash(x, SHA512),
]

# HMACs
for hf in (MD5, SHA):
    for keybyte in ('\x55', '\xaa', '\xff'):
        for keylen in (16, 32, 64):
            HASHINGS.append(lambda x,\
                hf=hf, keybyte=keybyte, keylen=keylen:\
                do_hmac(x, keybyte*keylen, hf))

# PBKDF2s
for n in (32, 64, 128, 512, 1024, 10, 100, 1000):
    for saltbyte in ('\x00', '\xff'):
        for saltlen in (8, 16, 32):
            HASHINGS.append(lambda x,\
                n=n, saltbyte=saltbyte, saltlen=saltlen:\
                PBKDF2(x, saltbyte*saltlen, count=n))


DECODINGS = (
    lambda h: (
        unpack('>L', h[:4])[0],
        unpack('>L', h[4:8])[0],
        unpack('>L', h[8:12])[0],
        unpack('>L', h[12:16])[0],),
    lambda h: (
        unpack('<L', h[:4])[0],
        unpack('<L', h[4:8])[0],
        unpack('<L', h[8:12])[0],
        unpack('<L', h[12:16])[0],),
)


MAXNUMS =\
    len(SEEDS) *\
    len(ENCODINGS) *\
    len(HASHINGS) *\
    len(DECODINGS)


def main():
    try:
        nbnums = int(sys.argv[1])
        if nbnums > MAXNUMS:
            raise ValueError
    except:
        print 'expected argument < %d (~2^%.2f)'\
            % (MAXNUMS, mp.log(MAXNUMS, 2))
        return -1
    count = 0

    for seed, encoding, hashing, decoding in\
        product(SEEDS, ENCODINGS, HASHINGS, DECODINGS):

        constants = decoding(hashing(encoding(seed)))

        for constant in constants:
            sys.stdout.write('%08x ' % constant)
        print
        count += 1
        if count == nbnums:
            return count


if __name__ == '__main__':
    sys.exit(main())
