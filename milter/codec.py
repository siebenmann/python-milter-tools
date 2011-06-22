#
# Encode and decode the milter protocol.
# This does not do any network conversation; it simply takes data buffers
# and decodes them to milter messages or encodes milter messages into a
# binary string.
#
import struct

# Milter constants
from consts import *

__doc__ = """Encode and decode the sendmail milter protocol.

This takes binary strings and decodes them to milter messages, or
encodes milter messages into binary strings.
"""
__all__ = ["MilterProtoError", "MilterIncomplete", "MilterDecodeError",
	   "encode_msg", "decode_msg", "pull_message", ]

# (Public) exceptions
class MilterProtoError(Exception):
	"""General encoding or decoding failure."""
	pass
class MilterIncomplete(MilterProtoError):
	"""The data buffer passed for decoding needs more data."""
	pass
class MilterDecodeError(MilterProtoError):
	"""The milter packet we are trying to decode is malformed."""
	pass

# This is effectively an internal exception; it is turned into either
# MilterIncomplete or MilterDecodeError.
class MilterNotEnough(MilterProtoError):
	"""Not enough data to finish decoding."""
	pass

# This maps milter commands and responses to the data structures that
# they use. The value is a tuple of (fieldname, fieldtype) tuples, in
# the order that they occur in the binary encoding.
codec = {
	SMFIC_ABORT: (),
	SMFIC_BODY: (('buf', 'str'),),
	SMFIC_CONNECT: (('hostname', 'str'),
			('family', 'char'),
			('port', 'u16'),
			('address', 'str'),),
	SMFIC_MACRO: (('cmdcode', 'char'),
		      ('nameval', 'strpairs')),
	SMFIC_BODYEOB: (),
	SMFIC_HELO: (('helo', 'str'),),
	SMFIC_HEADER: (('name', 'str'), ('value', 'str')),
	SMFIC_MAIL: (('args', 'strs'),),
	SMFIC_EOH: (),
	# It might be nice to decode bits for people, but that's too much
	# work for now.
	SMFIC_OPTNEG: (('version', 'u32'),
		       ('actions', 'u32'),
		       ('protocol', 'u32'),),
	SMFIC_RCPT: (('args', 'strs'),),
	SMFIC_QUIT: (),

	# Responses.
	SMFIR_ADDRCPT: (('rcpt', 'str'),),
	SMFIR_DELRCPT: (('rcpt', 'str'),),
	SMFIR_ACCEPT: (),
	SMFIR_REPLBODY: (('buf', 'str'),),
	SMFIR_CONTINUE: (),
	SMFIR_DISCARD: (),
	SMFIR_ADDHEADER: (('name', 'str'), ('value', 'str')),
	SMFIR_CHGHEADER: (('index', 'u32'), ('name', 'str'), ('value', 'str')),
	SMFIR_PROGRESS: (),
	SMFIR_QUARANTINE: (('reason', 'str'),),
	SMFIR_REJECT: (),
	SMFIR_TEMPFAIL: (),
	SMFIR_REPLYCODE: (('smtpcode', 'char3'),
			  ('space', 'char'),
			  ('text', 'str'),),
	# SMFIC_OPTNEG is also a valid response.
	}

#----
# Encoders and decoders for all of the different types we know about.

# Encoders take a value and return that value encoded as a binary string.
def encode_str(val):
	return "%s\0" % val
def encode_strs(val):
	return ''.join(encode_str(x) for x in val)
def encode_strpairs(val):
	if len(val) % 2 != 0:
		raise MilterProtoError("uneven number of name/value pairs")
	return encode_strs(val)
def encode_chr(val):
	return struct.pack('c', val)
def encode_u16(val):
	return struct.pack('!H', val)
def encode_u32(val):
	return struct.pack('!L', val)
def encode_chr3(val):
	if len(val) != 3:
		raise MilterProtoError("mis-sized chr3")
	return struct.pack('3s', val)

##
# decoding.
#
# Decoders take a data buffer and return the decoded value and the
# remaining data. If they have completely consumed the data, the
# remaining buffer is ''.

def unpack_n(data, fmt):
	"""Unpack a single struct module format item from data, returning
	the unpacked item and the remaining data. Raises MilterNotEnough
	if there is too little data to contain the item (eg, 3 bytes of
	data when we are decoding a 32-bit unsigned integer)."""
	nbytes = struct.calcsize(fmt)
	if len(data) < nbytes:
		raise MilterNotEnough("too little data")
	return (struct.unpack(fmt, data[:nbytes])[0], data[nbytes:])

def decode_chr(data):
	return unpack_n(data, 'c')
def decode_chr3(data):
	return unpack_n(data, '3s')
def decode_u16(data):
	return unpack_n(data, '!H')
def decode_u32(data):
	return unpack_n(data, '!L')
def decode_str(data):
	r = data.split('\0', 1)
	if len(r) != 2:
		raise MilterNotEnough("short string")
	return r[0], r[1]

# A string array consumes the rest of the data.
def decode_strs(data):
	r = []
	while data:
		s, data = decode_str(data)
		r.append(s)
	if not r:
		# <cks> believes that this is a requirement in the
		# milter protocol, at least implicitly.
		# You can argue about this for the SMFIC_MACRO; in theory
		# you could send a SMFIC_MACRO with empty macro definitions.
		raise MilterNotEnough("no strings in string array")
	return r, ''
def decode_strpairs(data):
	r, data = decode_strs(data)
	if len(r) % 2 != 0:
		raise MilterNotEnough("uneven string pairs")
	return r, data

codectypes = {
	'str': (encode_str, decode_str),
	'char': (encode_chr, decode_chr),
	'char3': (encode_chr3, decode_chr3),
	'u16': (encode_u16, decode_u16),
	'u32': (encode_u32, decode_u32),
	'strs': (encode_strs, decode_strs),
	'strpairs': (encode_strpairs, decode_strpairs),
	}
def encode(ctype, val):
	return codectypes[ctype][0](val)
def decode(ctype, data):
	return codectypes[ctype][1](data)

# A milter message itself is:
#	uint32 len
#	char   cmd
#	char   data[len-1]
def encode_msg(cmd, **kwargs):
	"""Encode a milter message to a binary string. Returns the string.

	The cmd argument is the milter command/response code. Parameters
	for the command are then given as keyword arguments, eg
	encode_msg('H', helo="localhost.localdomain")."""
	if cmd not in codec:
		raise MilterProtoError("encode: unknown command: "+cmd)
	parmlst = codec[cmd]
	parms = set([x[0] for x in parmlst])
	uparms = set(kwargs.keys())
	if parms != uparms:
		raise MilterProtoError("encode: parameter mismatch")
	data = []
	for name, ctype in parmlst:
		data.append(encode(ctype, (kwargs[name])))
	dstr = "".join(data)
	return struct.pack("!Lc", len(dstr) + 1, cmd) + dstr

def decode_msg(data):
	"""Decode data into a milter message.

	This returns a tuple of (cmd, msgstruct, remaining_data) where
	cmd is the milter command/response code, msgstruct is a dictionary
	of the per-message parameters, and remaining_data is any remaining
	data from the buffer. We raise MilterIncomplete if there is not
	enough data yet to fully decode the milter message; read more data
	and try again.
	"""
	# We need to read the initial message length and the command. If
	# we don't have that much, the message is clearly incomplete.
	try:
		mlen, data = decode_u32(data)
		if mlen == 0:
			raise MilterDecodeError("zero-length message")
		cmd, data = decode_chr(data)
	except MilterNotEnough:
		raise MilterIncomplete("need more data")
	if cmd not in codec:
		raise MilterDecodeError("decode: unknown command: "+cmd)
	# The rest of the packet is len-1 bytes long, so if we have less
	# data than that we need more.
	dlen = mlen-1
	if len(data) < dlen:
		raise MilterIncomplete("need more data")

	# From now onwards, a decoder raising MilterNotEnough means
	# that the structure inside the message packet was truncated or
	# incomplete, ie incorrectly encoded. This is a fatal error.
	rest = data[dlen:]
	buf = data[:dlen]
	rstruct = {}
	for name, ctype in codec[cmd]:
		try:
			rstruct[name], buf = decode(ctype, buf)
		except MilterNotEnough:
			raise MilterDecodeError("packet contents truncated")
	# If the packet buffer has remaining data, it means that there was
	# extra, un-consumed data after the data we expected. This is a fatal
	# encoding error.
	if len(buf) > 0:
		raise MilterDecodeError("decode: packet too long")
	return (cmd, rstruct, rest)

# Pull a message from data + an IO stream
def pull_message(data, stream, blksize = 1024):
	"""Pull a message from an existing data buffer and a stream. This
	returns the same thing that decode_msg() does. The stream must support
	.read(). The optional blksize parameter is the size of data blocks to
	try to read from the stream. Returns None on end of file, or raises
	MilterDecodeError if we saw EOF with an incomplete packet."""
	while 1:
		try:
			if data:
				return decode_msg(data)
		except MilterIncomplete:
			pass
		d1 = stream.recv(blksize)
		# Zero bytes read is end of file
		if not d1 and data:
			raise MilterDecodeError("packet truncated by EOF")
		elif not d1:
			return None
		data += d1
		del d1
