#
# TODO: we should have some real, validated binary messages so that we can
# test proper interoperability.

import unittest, struct

import codec

# A sample message for every milter protocol message that we know about.
sample_msgs = [
	('A', {}),
	('B', {'buf': 'abcdefghi\nthis is a test, yes.\n\t-cks'}),
	('C', {'hostname': 'localhost', 'family': '4', 'port': 3000,
	       'address': '127.0.0.1'}),
	('D', {'cmdcode': 'R', 'nameval': ['rcpt_mailer', 'abc',
					   'rcpt_host', 'localhost',
					   'rcpt_addr', 'cks']}),
	('E', {}),
	('H', {'helo': 'localhost.localdomain'}),
	('L', {'name': 'Subject', 'value': 'Tedium'}),
	('M', {'args': ['<>', 'haha']}),
	('N', {}),
	('O', {'version': 2, 'actions': 0x01, 'protocol': 0x02}),
	('R', {'args': ['<nosuch@cs.toronto.edu>', 'SIZE=100']}),
	('Q', {}),

	('+', {'rcpt': '<suchno@toronto.edu>'}),
	('-', {'rcpt': '<isthere@toronto.edu>'}),
	('a', {}),
	('b', {'buf': 'ARGLEBARGLE TEDIUM'}),
	('c', {}),
	('d', {}),
	('h', {'name': 'X-Annoyance', 'value': 'Testing'}),
	('m', {'index': 10, 'name': 'X-Spam-Goblets', 'value': '100% canned'}),
	('m', {'index': 1, 'name': 'Subject', 'value': ''}),
	('p', {}),
	('q', {'reason': 'Your mother was an Englishman'}),
	('r', {}),
	('t', {}),
	('y', {'smtpcode': '450', 'space': ' ', 'text': 'lazyness strikes'}),
	]

class basicTests(unittest.TestCase):
	def testMessageEncode(self):
		"""Can we encode every sample message to a non-zero message
		that has the cmd code as its fifth character?"""
		for cmd, args in sample_msgs:
			r = codec.encode_msg(cmd, **args)
			self.assertNotEqual(len(r), 0)
			self.assertTrue(len(r) >= 5)
			self.assertEqual(r[4], cmd)
			if not args:
				self.assertEqual(len(r), 5)

	def testMessageDecode(self):
		"""Test that encoded messages decode back to something that
		is identical to what we started with."""
		suffix = "\nabc"
		for cmd, args in sample_msgs:
			r = codec.encode_msg(cmd, **args)
			dcmd, dargs, rest = codec.decode_msg(r)
			self.assertEqual(cmd, dcmd)
			self.assertEqual(args, dargs)
			self.assertEqual(rest, '')
			# As a bonus, test that decoding with more data works
			# right for all messages.
			dcmd, dargs, rest = codec.decode_msg(r + suffix)
			self.assertEqual(rest, suffix)

	def testTruncatedDecode(self):
		"""Test that we signal not-enough on truncated decodes."""
		for cmd, args in sample_msgs:
			r = codec.encode_msg(cmd, **args)
			r = r[:-1]
			self.assertRaises(codec.MilterIncomplete,
					  codec.decode_msg, r)

	def testBrokenCommands(self):
		"""Sleazily test that we signal errors on malformed packets."""
		# Encode something that has no arguments.
		r = codec.encode_msg('A')
		# Break the command byte to something that doesn't exist.
		r = r[:4] + '!'
		self.assertRaises(codec.MilterDecodeError,
				  codec.decode_msg, r)
		# Break the command byte to something that requires arguments.
		r = r[:4] + 'D'
		self.assertRaises(codec.MilterDecodeError,
				  codec.decode_msg, r)
	def testBrokenLength(self):
		"""Sleazily test for a too-short version of every message."""
		minlen = struct.pack("!L", 1)
		for cmd, args in sample_msgs:
			# We can't shorten a message that has no arguments.
			if not args:
				continue
			r = codec.encode_msg(cmd, **args)
			tlen = struct.unpack("!L", r[:4])[0]
			tlen = tlen -1
			r = struct.pack("!L", tlen) + r[4:]
			self.assertRaises(codec.MilterDecodeError,
					  codec.decode_msg, r)
			# See what happens with a minimum-length message.
			r = minlen + r[4:]
			self.assertRaises(codec.MilterDecodeError,
					  codec.decode_msg, r)

	def testZeroLength(self):
		"""Trying to decode a zero-length message should fail with
		a decode error."""
		zlen = struct.pack("!L", 0)
		self.assertRaises(codec.MilterDecodeError,
				  codec.decode_msg, zlen)

	def testExtraArgsEncode(self):
		"""Test that adding arguments results in an encode error."""
		for cmd, args in sample_msgs:
			args = args.copy()
			args['blarg'] = 10
			self.assertRaises(codec.MilterProtoError,
					  codec.encode_msg, cmd,
					  **args)
	def testMissingArgsEncode(self):
		"""Test that removing arguments results in an encode error."""
		for cmd, args in sample_msgs:
			# Can't remove an argument if we don't have one
			if not args:
				continue
			args = args.copy()
			args.popitem()
			self.assertRaises(codec.MilterProtoError,
					  codec.encode_msg, cmd,
					  **args)

if __name__ == "__main__":
	unittest.main()
