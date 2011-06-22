#
# Support for having a milter protocol conversation over a network
# socket (or at least something that supports .recv).
# Much of this support is only useful for something doing the MTA side
# of the milter conversation.

from consts import *
import codec

__all__ = ['MilterConvoError', 'BufferedMilter',
	   'accept_reject_replies', 'bodyeob_replies',
	   ]

class MilterConvoError(Exception):
	"Raised on all conversation sequencing errors."""
	pass

# Specific command sets:
# accept/reject actions
accept_reject_replies = (SMFIR_ACCEPT, SMFIR_CONTINUE, SMFIR_REJECT,
			 SMFIR_TEMPFAIL, SMFIR_REPLYCODE)
# actions valid after BODYEOB
bodyeob_replies = accept_reject_replies + \
		  (SMFIR_ADDHEADER, SMFIR_CHGHEADER, SMFIR_REPLBODY,
		   SMFIR_ADDRCPT, SMFIR_DELRCPT)

class BufferedMilter(object):
	"""Maintain a buffered socket connection with another end that
	is speaking the milter protocol. This class supplies various
	convenience methods for handling aspects of the milter
	conversation."""
	def __init__(self, sock, blksize=16*1024):
		self.sock = sock
		self.buf = ''
		self.blksize = blksize

	def get_msg(self, eof_ok=False):
		"""Retrieve the next message from the connection message.
		Returns the decoded message as a tuple of (cmd, paramdict).
		Raises MilterDecodeError if we see EOF with an incomplete
		packet.

		If we see a clean EOF, we normally raise MilterConvoError.
		If eof_ok is True, we instead return None."""
		while 1:
			try:
				# .decode_msg will fail with an incomplete
				# error if self.buf is empty, so we don't
				# have to check for that ourselves.
				(rcmd, rdict, data) = codec.decode_msg(self.buf)
				self.buf = data
				return (rcmd, rdict)
			except codec.MilterIncomplete:
				# This falls through to cause us to read
				# stuff.
				pass
			
			data = self.sock.recv(self.blksize)
			# Check for EOF on the read.
			# If we have data left in self.buf, it axiomatically
			# failed to decode above and so it must be an
			# incomplete packet.
			if not data:
				if self.buf:
					raise codec.MilterDecodeError("packet truncated by EOF")
				elif not eof_ok:
					raise MilterConvoError("unexpected EOF")
				else:
					return None
			self.buf += data
			del data

	def get_real_msg(self, eof_ok=False):
		"""Read the next real message, one that is not a SMFIR_PROGRESS
		notification. The arguments are for get_msg."""
		while 1:
			r = self.get_msg(eof_ok)
			if not r or r[0] != SMFIR_PROGRESS:
				return r

	def send(self, cmd, **args):
		"""Send an encoded milter message. The arguments are the
		same arguments that codec.encode_msg() takes."""
		self.sock.sendall(codec.encode_msg(cmd, **args))

	def send_macro(self, cmdcode, **args):
		"""Send a SMFIC_MACRO message for the specific macro.
		The name and values are taken from the keyword arguments."""
		namevals = [x for items in args.items() for x in items]
		self.send(SMFIC_MACRO, cmdcode=cmdcode, nameval=namevals)

	# The following methods are only useful if you are handling
	# the MTA side of the milter conversation.
	def send_get(self, cmd, **args):
		"""Send a message (as with .send()) and then wait for
		a real reply message."""
		self.send(cmd, **args)
		return self.get_real_msg()

	def send_get_specific(self, reply_cmds, cmd, **args):
		"""Send a message and then wait for a real reply
		message. Raises MilterConvoError if the reply has a
		command code not in reply_cmds."""
		r = self.send_get(cmd, **args)
		if r[0] not in reply_cmds:
			raise MilterConvoError("unexpected response: "+r[0])
		return r

	def send_ar(self, cmd, **args):
		"""Send a message and then wait for a real reply message
		that is from the accept/reject set."""
		return self.send_get_specific(accept_reject_replies,
					      cmd, **args)

	def send_body(self, body):
		"""Send the body of a message, properly chunked and
		handling progress. Returns a progress response. If it
		is anything except SMFIR_CONTINUE, processing cannot
		continue because the body may not have been fully
		transmitted."""
		for cstart in range(0, len(body), MILTER_CHUNK_SIZE):
			cend = cstart+MILTER_CHUNK_SIZE
			blob = body[cstart:cend]
			r = self.send_ar(SMFIC_BODY, buf=blob)
			# Some responses require an immediate abort, some
			# allow it as a MAY, and some are silent. We choose
			# to immediately abort on all non-continue responses
			# because this is a) simple and b) apparently spec
			# compliant (to the extent that we even have a formal
			# spec).
			if r[0] != SMFIR_CONTINUE:
				break
		return r

	def send_headers(self, headertuples):
		"""Send message headers, handling progress; returns a
		progress response, normally SMFIR_CONTINUE. headertuples
		is a sequence of (header-name, header-value) tuples.

		If the response is anything but SMFIR_CONTINUE,
		processing cannot continue because the headers may not
		have been completely transmitted."""
		for hname, hval in headertuples:
			r = self.send_ar(SMFIC_HEADER, name=hname, value=hval)
			# As above, we immediately stop if we get a
			# non-continue response.
			if r[0] != SMFIR_CONTINUE:
				break
		return r
