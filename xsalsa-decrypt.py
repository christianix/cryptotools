#!/usr/bin/python3

import sys
from salsa import XSalsa20

def hexdump(data):
	"""Convert byte array to hex string"""

	return ' '.join(["{:02X}".format(v) for v in data])

#
# MAIN
#

if len(sys.argv) < 3:
	print("Usage: {} NONCE.bin KEY.bin CIPHER.bin".format(sys.argv[0]))
	sys.exit(-1)

with open(sys.argv[1], "rb") as f:
	nonce = f.read()

with open(sys.argv[2], "rb") as f:
	key = f.read()

with open(sys.argv[3], "rb") as f:
	cipher = f.read()

# Build input of salsa
kdfinput = {}
kdfinput["nonce"] = nonce
kdfinput["counter"] = 0
kdfinput["key"] = key

xsalsa = XSalsa20()
ks = xsalsa(**kdfinput)
plain = bytes(k ^ c for (k, c) in zip(ks, cipher))

print("Plain: {}".format(hexdump(plain)))
