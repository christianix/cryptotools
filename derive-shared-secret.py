#!/usr/bin/python3

import sys
import cypari2
from cypari2.convert import gen_to_integer, integer_to_gen

def hexdump(b):
	"""Convert byte array to hex string"""

	return ' '.join(["{:02X}".format(v) for v in b])

def clamp(n):
	"""Curve25519 clamping by Matthew Dempsky"""

	n &= ~7
	n &= ~(128 << 8 * 31)
	n |= 64 << 8 * 31
	return n

def curve25519_pk_mult(pari, s, x):
	# E: y^2 = x^3 + 486662 * x^2 + x on GF(2^255-19)
	E = pari.ellinit([0,486662,0,1,0], 2**255-19)
	x_elem = pari.Mod(x, 2**255-19)
	# y = Sqrt(x^3 + 486662 * x^2 + x)
	y = x**3 + 486662 * x**2 + x
	y_elem = pari.sqrt(pari.Mod(y, 2**255-19))
	P = [x_elem, y_elem]
	return pari.ellmul(E, P, s)

if len(sys.argv) < 3:
	print("Usage: {} MY_SK_FILE OTHER_PK_FILE".format(sys.argv[0]))
	sys.exit(-1)

# Open file with my SK
with open(sys.argv[1], "rb") as f:
    my_sk_bytes = f.read()

# Open file with other PK
with open(sys.argv[2], "rb") as f:
    other_pk_bytes = f.read()

# Convert and clamp SK
my_sk = int.from_bytes( my_sk_bytes, "little" )
my_sk = clamp(my_sk)

# Init Pari
pari = cypari2.Pari()

# Read and convert PK
other_pk = int.from_bytes( other_pk_bytes, "little" )
shared_p = curve25519_pk_mult(pari, my_sk, other_pk)

shared_i = gen_to_integer(pari.lift(shared_p[0]))
shared_sk = shared_i.to_bytes(32, byteorder='little')

# Print PK as hex dump
print(hexdump(shared_sk))
