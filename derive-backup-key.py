#!/usr/bin/python3

import sys
import hashlib

def hexdump(b):
	"""Convert byte array to hex string"""

	return ' '.join(["{:02X}".format(v) for v in b])

#
# MAIN
#

if len(sys.argv) < 2:
	print("Usage: {} SALT.bin PASSWD.txt".format(sys.argv[0]))
	sys.exit(-1)

with open(sys.argv[1], mode='rb') as file:
	salt = file.read()

with open(sys.argv[2], mode='r') as file:
	pwd = bytes(file.readline().rstrip('\n'), 'utf-8')

Kenc = hashlib.pbkdf2_hmac('sha256', pwd, salt, 100000, 32)

print("Backup key: {}".format(hexdump(Kenc)))
