#!/usr/bin/python

import pysha1

salt = "s3cRe7-#!@~"
msg = "from=123&to=456&amount=50"
(h0,h1,h2,h3,h4) = pysha1.sha1(salt + msg)
print("original hash: %8x%8x%8x%8x%8x" % (h0,h1,h2,h3,h4))

injection = "&to=666&amount=99999"
forged_msg = pysha1.pad(msg) + injection	# recreate the original chunk and add our injection
padded = pysha1.pad(forged_msg, 64 + len(injection))	# pad
padded = padded[-64:]		# take only the last chunk

(h0,h1,h2,h3,h4) = pysha1.sha1_impl(padded, h0,h1,h2,h3,h4) # hash it, reusing the original output as input.
print("generated this without using the salt: %8x%8x%8x%8x%8x\n" % (h0,h1,h2,h3,h4))

# verify that it works with the salt
salt_len = 11	# assumption
forged_msg = (pysha1.pad(msg, len(msg)+salt_len) + injection)
print "forged message: ", ["%02x" % ord(c) for c in forged_msg]
(h0,h1,h2,h3,h4) = pysha1.sha1(salt + forged_msg)
print("and its signature, using the salt: %8x%8x%8x%8x%8x" % (h0,h1,h2,h3,h4))
