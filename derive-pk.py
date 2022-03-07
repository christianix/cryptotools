#!/usr/bin/python3

import sys
import cypari2
from cypari2.convert import gen_to_integer

def hexdump(b):
	"""Convert byte array to hex string"""

	return ' '.join(["{:02X}".format(v) for v in b])

def clamp(n):
	"""Curve25519 clamping by Matthew Dempsky"""

	n &= ~7
	n &= ~(128 << 8 * 31)
	n |= 64 << 8 * 31
	return n

if len(sys.argv) < 2:
	print("Usage: {} SK_FILE".format(sys.argv[0]))
	sys.exit(-1)

#
# Initialize EC
#
# E: y^2 = x^3 + 486662 * x^2 + x on GF(2^255-19)
# X0 = (9, Sqrt(39420360)), because 9^3 + 486662 * 9^2 + 9 = 39420360
pari = cypari2.Pari()
E = pari.ellinit([0,486662,0,1,0], 2**255-19)
P = [pari.Mod(9, 2**255-19), pari.sqrt(pari.Mod(39420360, 2**255-19))]

# Open file with SK
with open(sys.argv[1], "rb") as f:
    sk_bytes = f.read()

# Convert and clamp SK
sk = int.from_bytes( sk_bytes, "little" )
n = clamp(sk)

# Derive PK
pk_p = pari.ellmul(E, P, n)
pk_i = gen_to_integer(pari.lift(pk_p[0]))
pk = pk_i.to_bytes(32, byteorder='little')

# Print PK as hex dump
print(hexdump(pk))
