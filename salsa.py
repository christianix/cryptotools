import struct

class HSalsa20:
	"""
	Based on scripts by
		- Daniel J. Bernstein. "Cryptography in NaCl".
		- Matthew Dempsky. https://github.com/Daeinar/salsa20.
	"""

	def __init__(self, r=20):
		assert r >= 0
		self._rounds = r # number of rounds
		self._state = [0] * 16

	@property
	def state(self):
		"""Get internal state."""
		return self._state

	@state.setter
	def state(self, values):
		"""Set internal state with tuple (nonce, key)."""
		try:
			nonce, key = values
		except ValueError:
			raise ValueError("Setting state requires a tuple with nonce and key")
		else:
			self._state[::5] = struct.unpack('<4I', b'expand 32-byte k')
			self._state[1:5] = key[:4]
			self._state[6:10] = nonce
			self._state[11:15] = key[4:]

	def __call__(self, nonce=[0]*16, key=[0]*32):
		assert len(nonce) == 16
		assert len(key) == 32

		# Convert input byte stream to little endian words
		n = struct.unpack('<4I', nonce)
		k = struct.unpack('<8I', key)

		# Set state
		self.state = (n, k)

		# Do calculation
		for i in range(self._rounds//2): self.doubleround()

		# Convert result to output byte stream
		s = [self._state[i] for i in [0,5,10,15,6,7,8,9]]
		return struct.pack('<8I',*s)

	def doubleround(self):
		self.__columnround__()
		self.__rowround__()

	def __step__(self, i, j, k, r):
		self._state[i] ^= HSalsa20.rotate(self._state[j] + self._state[k], r)

	def __quarterround__(self, i0, i1, i2, i3):
		self.__step__(i1, i0, i3, 7)
		self.__step__(i2, i1, i0, 9)
		self.__step__(i3, i2, i1, 13)
		self.__step__(i0, i3, i2, 18)

	def __rowround__(self):
		self.__quarterround__(0, 1, 2, 3)
		self.__quarterround__(5, 6, 7, 4)
		self.__quarterround__(10, 11, 8, 9)
		self.__quarterround__(15, 12, 13, 14)

	def __columnround__(self):
		self.__quarterround__(0, 4, 8, 12)
		self.__quarterround__(5, 9, 13, 1)
		self.__quarterround__(10, 14, 2, 6)
		self.__quarterround__(15, 3, 7, 11)

	@staticmethod
	def rotate(x, n):
		x &= 0xffffffff
		return ((x << n) | (x >> (32 - n))) & 0xffffffff

class Salsa20(HSalsa20):
	def __init__(self, r=20):
		super().__init__(r)

	def __call__(self, nonce=[0]*8, counter=0, key=[0]*32):
		assert len(nonce) == 8
		assert counter >= 0
		assert len(key) == 32

		# Convert input byte stream to little endian words
		n = struct.unpack('<2I', nonce)
		n = n + struct.unpack('<2I', counter.to_bytes(8, byteorder='little'))
		k = struct.unpack('<8I', key)

		# Set state
		self.state = (n, k)
		s = self.state[:]

		# Do calculation
		for i in range(self._rounds//2): self.doubleround()

		# Add initial state to the final one
		for i in range(16):
			self._state[i] = (self._state[i] + s[i]) & 0xffffffff

		return struct.pack('<16I',*self._state)

class XSalsa20(Salsa20):
	def __init__(self, r=20):
		super().__init__(r)

	def __call__(self, nonce=[0]*24, counter=0, key=[0]*32):
		assert len(nonce) == 24
		assert counter >= 0
		assert len(key) == 32

		# Derive k1:
		hsalsa = HSalsa20(self._rounds)
		k_one = hsalsa(nonce[:16], key)

		return super().__call__(nonce[16:], counter, k_one)

