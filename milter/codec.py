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
	   "encode_msg", "decode_msg", "optneg_capable", "encode_optneg",]

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
#
# A note:
# The reverse engineered spec I've seen says that SMFIR_REPLBODY is
# the entire new body as one message and is a null-terminated string.
# This is wrong. Experience with PureMessage and inspection of the
# sendmail source code says that both SMFIC_BODY and SMFIR_REPLBODY
# are simply character blocks, and in fact are supposed to have
# bare LF converted to CRLF when sending to the milter and converted
# back to a bare LF on receive. (We opt not to try to do that at this
# level, since it may require spanning block buffers.)
# Like SMFIC_BODY, SMFIR_REPLBODY may be sent multiple times (and there
# is no requirement that the chunks be large).
#
codec = {
	SMFIC_ABORT: (),
	SMFIC_BODY: (('buf', 'buf'),),
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
	SMFIR_REPLBODY: (('buf', 'buf'),),
	SMFIR_CONTINUE: (),
	SMFIR_DISCARD: (),
	SMFIR_ADDHEADER: (('name', 'str'), ('value', 'str')),
	SMFIR_CHGHEADER: (('index', 'u32'), ('name', 'str'), ('value', 'str')),
	SMFIR_PROGRESS: (),
	SMFIR_QUARANTINE: (('reason', 'str'),),
	SMFIR_REJECT: (),
	SMFIR_TEMPFAIL: (),
	# It is kind of lame that we force people to explicitly encode
	# the space field (with a ' ', to be spec-compliant). But doing
	# a nicer version requires building an encoding/decoding system
	# that knows about padding fields, just for this one field in one
	# message.
	SMFIR_REPLYCODE: (('smtpcode', 'char3'),
			  ('space', 'char'),
			  ('text', 'str'),),
	# SMFIC_OPTNEG is also a valid response.
	}

#----
# Encoders and decoders for all of the different types we know about.
#
# Content constraints:
# char3: must have exactly three characters. We explicitly check this
#        only on encode; on decode it is implicitly checked by the field
#	 specification.
# strpairs: this generates an array, so we check that the array has an
#	 even number of elements (ie, has pairs). The array is allowed
#	 to be empty; as far as I can see, it is and should be valid to
#	 send a SMFIC_MACRO with no macro values set.
# strs:  this generates an array and we insist that the array has at least
#	 one value. 'strs' is used only by SMFIC_MAIL and SMFIC_RCPT,
#	 and the spec requires that the first array element is the actual
#	 argument ... which must exist, even if it is '<>' for a null sender
#	 or recipient.
#
# (Because the 'strs' encoder and decoder are also used by strpairs, they
# take a private argument to control this behavior.)

# Encoders take a value and return that value encoded as a binary string.
def encode_buf(val):
	return val
def encode_str(val):
	return "%s\0" % val
def encode_strs(val, empty_ok = False):
	if len(val) == 0 and not empty_ok:
		# See comment above for why this is justified.
		raise MilterProtoError("empty string array")
	return ''.join(encode_str(x) for x in val)
def encode_strpairs(val):
	if len(val) % 2 != 0:
		raise MilterProtoError("uneven number of name/value pairs")
	return encode_strs(val, empty_ok = True)
def encode_chr(val):
	return struct.pack('c', val)
def encode_u16(val):
	return struct.pack('!H', val)
def encode_u32(val):
	return struct.pack('!L', val)
def encode_chr3(val):
	if len(val) != 3:
		raise MilterProtoError("mis-sized char3")
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

# A buffer necessarily consumes all remaining data, since it has no
# terminator.
def decode_buf(data):
	return data, ''

# A string array consumes the rest of the data.
def decode_strs(data, empty_ok = False):
	r = []
	while data:
		s, data = decode_str(data)
		r.append(s)
	if not empty_ok and not r:
		# See comment above for why this is justified.
		raise MilterNotEnough("no strings in string array")
	return r, ''
def decode_strpairs(data):
	r, data = decode_strs(data, empty_ok = True)
	if len(r) % 2 != 0:
		raise MilterNotEnough("uneven string pairs")
	return r, data

codectypes = {
	'buf': (encode_buf, decode_buf),
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
	rawdata = data
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
			# This is an obsessively detailed exception.
			# It was necessary.
			raise MilterDecodeError("packet contents for '%s' truncated decoding %s: %d / %s / %s" % (cmd, ctype, mlen, repr(buf), repr(rawdata[:mlen+10])))
	# If the packet buffer has remaining data, it means that there was
	# extra, un-consumed data after the data we expected. This is a fatal
	# encoding error.
	if len(buf) > 0:
		raise MilterDecodeError("decode: packet too long. packet type: '%s', len %d, remaining: %s raw %s" % (cmd, mlen, repr(buf), repr(rawdata[:mlen+4])))
	return (cmd, rstruct, rest)

# Option negotiation is somewhat complex.
# First, we can't claim to support things that this module can't handle.
# Next, we can't accept (or claim to accept) things that the other end
# told us it can't handle.
# Finally, while we theoretically can advertise support for less than
# the full V2 protocol, there are milters that object to this to the
# extent that they just drop the connection.
#
# Note that the protocol handling is significantly different from the
# actions handling. In actions, the MTA advertises what actions the
# milter can perform and the milter replies with what actions out of
# them that it may perform; in the simple case this is SMFI_V2_ACTS
# from the MTA and SMFI_V2_ACTS back from the milter.  In protocol,
# the MTA advertises what protocol steps it supports skipping and the
# milter replies with what protocol steps *should* be skipped.
# The common case is that the milter client wants all steps that are
# in the V2 protocol and not any steps that aren't.
def optneg_mta_capable(actions, protocol):
	"""Return a bitmask of actions and protocols that milter.codec
	can support."""
	return (actions & SMFI_V2_ACTS, protocol & SMFI_V2_PROT)
def optneg_milter_capable(ractions, rprotocol,
			  actions=SMFI_V2_ACTS, protocol=0x0):
	"""Given an MTA's actions and protocol, and our actions and
	protocol, return an (actions, protocol) tuple suitable for
	use in a SMFIC_OPTNEG reply. Since our protocol is the steps
	we wish the MTA to exclude, it will often be zero."""
	actions = actions & SMFI_V2_ACTS
	oactions = ractions & actions
	pmask = protocol | (0xfffffff ^ SMFI_V2_PROT)
	oprotocol = rprotocol & pmask
	return (oactions, oprotocol)

def encode_optneg(actions, protocol, is_milter=False):
	"""Encode a SMFIC_OPTNEG message based on the supplied actions
	and protocol. Actions and protocol should normally have been
	passed through either optneg_mta_capable() or
	optneg_milter_capable()	depending on which side of the protocol
	you are implementing."""
	# We never encode any actions beyond what we support.
	actions = actions & SMFI_V2_ACTS
	# Unless we are handling the milter side of the protocol,
	# clamp the protocol bitmask to what we support.
	if not is_milter:
		protocol = protocol & SMFI_V2_PROT
	return encode_msg(SMFIC_OPTNEG, version=MILTER_VERSION,
			  actions=actions, protocol=protocol)
