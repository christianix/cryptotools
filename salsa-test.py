#!/usr/bin/python3

from salsa import HSalsa20, Salsa20, XSalsa20
import hashlib

def hexdump(data):
	"""Convert byte array to hex string"""

	return ' '.join(["{:02X}".format(v) for v in data])

def run_test(alg, tname, tparam, expected):
	print('Test case {}: '.format(tname), end='')
	result = alg(**tparam)
	if result == expected:
		print('Success')
	else:
		print('Failed:\n    Result = {}\n    Expected: {}'.format(hexdump(result), hexdump(expected)))

#
# HSalsa20 Tests
#

hsalsa = HSalsa20()

# Test 1: HSalsa20(k, 0)
tvector = dict()
tvector["nonce"] = bytearray(16)
tvector["key"] = bytearray.fromhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
expected = bytearray.fromhex("1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389")
run_test(hsalsa, '1 - HSalsa20(k, 0)', tvector, expected)

# Test 2: HSalsa20(k1 , n1)
tvector.clear()
tvector["nonce"] = bytearray.fromhex("69696ee955b62b73cd62bda875fc73d6")
tvector["key"] = bytearray.fromhex("1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389")
expected = bytearray.fromhex("dc908dda0b9344a953629b733820778880f3ceb421bb61b91cbd4c3e66256ce4")
run_test(hsalsa, '2 - HSalsa20(k1, n1)', tvector, expected)

#
# Salsa20 Tests
#

salsa = Salsa20()

# Test 3: Vector 0
tvector.clear()
tvector["nonce"] = bytearray.fromhex("0000000000000000")
tvector["counter"] = 0
tvector["key"] = bytearray.fromhex("8000000000000000000000000000000000000000000000000000000000000000")
expected = bytearray.fromhex("E3BE8FDD8BECA2E3EA8EF9475B29A6E7003951E1097A5C38D23B7A5FAD9F6844B22C97559E2723C7CBBD3FE4FC8D9A0744652A83E72A9C461876AF4D7EF1A117")
run_test(salsa, '3 - Vector 0', tvector, expected)

# Test 4: Vector 9
tvector.clear()
tvector["nonce"] = bytearray.fromhex("0000000000000000")
tvector["counter"] = 0
tvector["key"] = bytearray.fromhex("0040000000000000000000000000000000000000000000000000000000000000")
expected = bytearray.fromhex("01F191C3A1F2CC6EBED78095A05E062E1228154AF6BAE80A0E1A61DF2AE15FBCC37286440F66780761413F23B0C2C9E4678C628C5E7FB48C6EC1D82D47117D9F")
run_test(salsa, '4 - Vector 9', tvector, expected)

# Test 5: Salsa20(k2 , n2)
nonce = bytearray.fromhex("8219e0036b7a0b37")
c = 0
key = bytearray.fromhex("dc908dda0b9344a953629b733820778880f3ceb421bb61b91cbd4c3e66256ce4") 
expected = bytearray.fromhex("662b9d0e3463029156069b12f918691a98f7dfb2ca0393c96bbfc6b1fbd630a2")
print('Test case 5 - Salsa20(k2, n): ', end='')
digest = hashlib.sha256()
for i in range(65536):
	digest.update(salsa(nonce, c, key))
	c += 1
if digest.digest() == expected:
	print('Success')
else:
	print('Failed')

#
# XSalsa20 Tests
#

xsalsa = XSalsa20()

# Test 6: Chapter 10
tvector.clear()

tvector["nonce"] = bytearray(16)
tvector["key"] = bytearray.fromhex("4A5D9D5BA4CE2DE1728E3BF480350F25E07E21C947D19E3376F09B3C1E161742")
k1 = hsalsa(**tvector)
tvector.clear()
tvector["nonce"] = bytearray.fromhex("69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37")
tvector["counter"] = 0
tvector["key"] = k1
expected = bytearray.fromhex("eea6a7251c1e72916d11c2cb214d3c252539121d8e234e652d651fa4c8cff880309e645a74e9e0a60d8243acd9177ab51a1beb8d5a2f5d700c093c5e55855796")
run_test(xsalsa, '6 - Chaper 10', tvector, expected)

