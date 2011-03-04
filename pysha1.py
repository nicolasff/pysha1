import struct, sys, hashlib
top = 0xffffffff

def rotl(i, n):
	lmask = top << (32-n)
	rmask = top >> n
	l = i & lmask
	r = i & rmask
	newl = r << n
	newr = l >> (32-n)
	return newl + newr

def add(l):
	ret = 0
	for e in l:
		ret = (ret + e) & top
	return ret


def sha1_impl(msg, h0, h1, h2, h3, h4):

	for j in xrange(len(msg) / 64):
		chunk = msg[j * 64: (j+1) * 64]

		w = {}
		for i in xrange(16):
			word = chunk[i*4: (i+1)*4]
			(w[i],) = struct.unpack(">i", word)
		
		for i in range(16, 80):
			w[i] = rotl((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]) & top, 1)

		a = h0
		b = h1
		c = h2
		d = h3
		e = h4

		for i in range(0, 80):
			if 0 <= i <= 19:
				f = (b & c) | ((~ b) & d)
				k = 0x5A827999
			elif 20 <= i <= 39:
				f = b ^ c ^ d
				k = 0x6ED9EBA1
			elif 40 <= i <= 59:
				f = (b & c) | (b & d) | (c & d)
				k = 0x8F1BBCDC
			elif 60 <= i <= 79:
				f = b ^ c ^ d
				k = 0xCA62C1D6

			temp = add([rotl(a, 5), f, e, k, w[i]])
			e = d
			d = c
			c = rotl(b, 30)
			b = a
			a = temp

		h0 = add([h0, a])
		h1 = add([h1, b])
		h2 = add([h2, c])
		h3 = add([h3, d])
		h4 = add([h4, e])

	return (h0, h1, h2, h3, h4)

def pad(msg, sz = None):
	if sz == None:
		sz = len(msg)
	bits = sz * 8
	padding = 512 - ((bits + 8) % 512) - 64

	msg += "\x80"	# append bit "1", and a few zeros.
	return msg + (padding / 8) * "\x00" + struct.pack(">q", bits) # don't count the \x80 here, hence the -8.

def sha1(msg):
	return sha1_impl(pad(msg), 0x67452301 , 0xefcdab89 , 0x98badcfe , 0x10325476 , 0xc3d2e1f0)

