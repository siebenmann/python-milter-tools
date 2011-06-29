#
# It is quite likely that these tests are overly peculiar.
#
# test milter.convo.
# assumes that the milter.codec module works.
#
import unittest

import codec
import convo
from consts import *

class ConvError(Exception):
	pass

# ---
# test infrastructure

# These are from the perspective of the socket; it expects you to read
# or write.
READ, WRITE = object(), object()

# A fake socket object that implements .recv() and .sendall().
# It is fed a conversation that it expects (a sequence of read and
# write operations), and then verifies that the sequence that happens
# is what you told it to expect.
# Because this is specific to verifying the milter conversation, it
# does not bother having to know exactly what the written messages are;
# for our purpose, it is enough to know their type.
class FakeSocket(object):
	def __init__(self, conv=None):
		if conv is None:
			conv = []
		self.conv = conv
		self.cindex = 0

	# verify that a .recv() or .sendall() is proper, ie that it
	# is the next expected action.
	def _verify_conv(self, adir):
		if self.cindex >= len(self.conv):
			raise ConvError("unexpected action")
		if adir != self.conv[self.cindex][0]:
			raise ConvError("sequence mismatch")

	def _add(self, adir, what):
		self.conv.append((adir, what))
	def addReadMsg(self, cmd, **args):
		"""Add a message to be read; arguments are as per
		encode_msg."""
		self._add(READ, codec.encode_msg(cmd, **args))
	def addRead(self, buf):
		"""Add a raw string to be read."""
		self._add(READ, buf)
	def addWrite(self, cmd):
		"""Add an expected write command."""
		self._add(WRITE, cmd)
	def addMTAWrite(self, cmd):
		"""Add an expected write command and then a SMFIR_CONTINUE
		reply to it."""
		self._add(WRITE, cmd)
		self.addReadMsg(SMFIR_CONTINUE)

	def isEmpty(self):
		"""Returns whether or not all expected reads and writes
		have been consumed."""
		return self.cindex == len(self.conv)

	#
	# The actual socket routines we emulate.
	def recv(self, nbytes):
		self._verify_conv(READ)
		# nbytes should be at least as large as what we are
		# scheduled to send.
		_, obj = self.conv[self.cindex]
		self.cindex += 1
		if isinstance(obj, (list, tuple)):
			obj = codec.encode_msg(obj[0], **obj[1])
		if (len(obj) > nbytes):
			raise ConvError("short read")
		return obj

	def sendall(self, buf):
		self._verify_conv(WRITE)
		# We verify that we got the right sort of stuff
		r = codec.decode_msg(buf)
		_, otype = self.conv[self.cindex]
		self.cindex += 1
		if r[0] != otype:
			raise ConvError("received unexpected reply '%s' vs '%s" % \
					(r[0], otype))

# -----
#
class basicTests(unittest.TestCase):
	def testShortReads(self):
		"""Test that we correctly read multiple times to reassemble
		a short message, and that we get the right answer."""
		ams = SMFIC_CONNECT
		adict = { 'hostname': 'localhost',
			  'family': '4',
			  'port': 1678,
			  'address': '127.10.10.1' }
		msg = codec.encode_msg(ams, **adict)
		msg1, msg2 = msg[:10], msg[10:]		
		s = FakeSocket()
		s.addRead(msg1); s.addRead(msg2)

		mbuf = convo.BufferedMilter(s)
		rcmd, rdict = mbuf.get_msg()
		self.assertEqual(ams, rcmd)
		self.assertEqual(adict, rdict)
		self.assertTrue(s.isEmpty())

	def testProgressReads(self):
		"""Test that we correctly read multiple progress messages
		before getting the real one."""
		s = FakeSocket()
		s.addReadMsg(SMFIR_PROGRESS)
		s.addReadMsg(SMFIR_PROGRESS)
		s.addReadMsg(SMFIR_PROGRESS)
		s.addReadMsg(SMFIR_DELRCPT, rcpt=["<a@b.c>",])
		mbuf = convo.BufferedMilter(s)
		rcmd, rdict = mbuf.get_real_msg()
		self.assertEqual(rcmd, SMFIR_DELRCPT)
		self.assertTrue(s.isEmpty())

class continuedTests(unittest.TestCase):
	def testHeaders(self):
		"""Test that we handle writing a sequence of headers in
		the way that we expect."""
		s = FakeSocket()
		hdrs = (('From', 'Chris'), ('To', 'Simon'), ('Subject', 'Yak'))
		for _ in hdrs:
			s.addMTAWrite(SMFIC_HEADER)
		mbuf = convo.BufferedMilter(s)
		rcmd, rdict = mbuf.send_headers(hdrs)
		self.assertEqual(rcmd, SMFIR_CONTINUE)
		self.assertTrue(s.isEmpty())

	def testShortHeaders(self):
		"""Test that we return early from a series of header writes
		if SMFIR_CONTINUE is not the code returned."""
		s = FakeSocket()
		hdrs = (('From', 'Chris'), ('To', 'Simon'), ('Subject', 'Yak'))
		s.addMTAWrite(SMFIC_HEADER)
		s.addWrite(SMFIC_HEADER)
		s.addReadMsg(SMFIR_ACCEPT)
		rcmd, rdict = convo.BufferedMilter(s).send_headers(hdrs)
		self.assertEqual(rcmd, SMFIR_ACCEPT)
		self.assertTrue(s.isEmpty())

	def testBodySequence(self):
		"""Test that we handle writing a large body in the way
		we expect."""
		s = FakeSocket()
		body = ('*' * MILTER_CHUNK_SIZE) * 3
		s.addMTAWrite(SMFIC_BODY)
		s.addMTAWrite(SMFIC_BODY)
		s.addMTAWrite(SMFIC_BODY)
		mbuf = convo.BufferedMilter(s)
		rcmd, rdict = mbuf.send_body(body)
		self.assertEqual(rcmd, SMFIR_CONTINUE)
		self.assertTrue(s.isEmpty())

	def testShortBody(self):
		"""Test that we return early from a series of body writes
		if SMFIR_CONTINUE is not the code returned."""
		s = FakeSocket()
		body = ('*' * MILTER_CHUNK_SIZE) * 3
		s.addMTAWrite(SMFIC_BODY)
		s.addWrite(SMFIC_BODY)
		s.addReadMsg(SMFIR_ACCEPT)
		rcmd, rdict = convo.BufferedMilter(s).send_body(body)
		self.assertEqual(rcmd, SMFIR_ACCEPT)
		self.assertTrue(s.isEmpty())

	optneg_mta_pairs = (
		((SMFI_V2_ACTS, SMFI_V2_PROT), (SMFI_V2_ACTS, SMFI_V2_PROT)),
		((0x10, 0x10), (0x10, 0x10)),
		((0xff, 0xff), (SMFI_V2_ACTS, SMFI_V2_PROT)),
		)
	def testMTAOptneg(self):
		"""Test that the MTA version of option negotiation returns
		what we expect it to."""
		for a, b in self.optneg_mta_pairs:
			s = FakeSocket()
			s.addWrite(SMFIC_OPTNEG)
			s.addReadMsg(SMFIC_OPTNEG, version=MILTER_VERSION,
				     actions=a[0], protocol=a[1])
			# strict=True would blow up on the last test.
			ract, rprot = convo.BufferedMilter(s).optneg_mta(strict=False)
			self.assertEqual(ract, b[0])
			self.assertEqual(rprot, b[1])

	optneg_exc_errors = ((SMFI_V2_ACTS, 0xff),
			     (0xff, SMFI_V2_PROT),
			     (0xff, 0xff),)
	def testMilterONOutside(self):
		"""Test that the MTA version of option negotiation errors
		out if there are excess bits in the milter reply."""
		for act, prot in self.optneg_exc_errors:
			s = FakeSocket()
			s.addWrite(SMFIC_OPTNEG)
			s.addReadMsg(SMFIC_OPTNEG, version=MILTER_VERSION,
				     actions=act, protocol=prot)
			bm = convo.BufferedMilter(s)
			self.assertRaises(convo.MilterConvoError,
					  bm.optneg_mta)

	def testMilterOptneg(self):
		"""Test the milter version of option negotiation."""
		for a, b in self.optneg_mta_pairs:
			s = FakeSocket()
			s.addReadMsg(SMFIC_OPTNEG, version=MILTER_VERSION,
				     actions=a[0], protocol=a[1])
			s.addWrite(SMFIC_OPTNEG)
			ract, rprot = convo.BufferedMilter(s).optneg_milter()
			self.assertEqual(ract, b[0])
			self.assertEqual(rprot, b[1])
			# TODO: we should somehow examine the message that
			# optneg_milter() writes to the socket. But this
			# requires features that we do not have in our
			# fake sockets...

if __name__ == "__main__":
	unittest.main()
