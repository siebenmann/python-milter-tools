#
# Constants for the milter protocol.

# Milter protocol constants.

MILTER_VERSION = 2 # Milter version we claim to speak (from pmilter)
MILTER_CHUNK_SIZE = 65535 # How large a SMFIC_BODY body can be

# Potential milter command codes and their corresponding PpyMilter callbacks.
# From sendmail's include/libmilter/mfdef.h
SMFIC_ABORT   = 'A' # "Abort"
SMFIC_BODY    = 'B' # "Body chunk"
SMFIC_CONNECT = 'C' # "Connection information"
SMFIC_MACRO   = 'D' # "Define macro"
SMFIC_BODYEOB = 'E' # "final body chunk (End)"
SMFIC_HELO    = 'H' # "HELO/EHLO"
SMFIC_HEADER  = 'L' # "Header"
SMFIC_MAIL    = 'M' # "MAIL from"
SMFIC_EOH     = 'N' # "EOH"
SMFIC_OPTNEG  = 'O' # "Option negotation"
SMFIC_RCPT    = 'R' # "RCPT to"
SMFIC_QUIT    = 'Q' # "QUIT"
SMFIC_DATA    = 'T' # "DATA"

# From the milter documentation.
# Things that milters can do:
SMFIF_ADDHDRS	= 0x01
SMFIF_CHGBODY	= 0x02
SMFIF_ADDRCPT	= 0x04
SMFIF_DELRCPT	= 0x08
SMFIF_CHGHDRS	= 0x10
SMFIF_QUARANTINE = 0x20

# From sendmail's include/libmilter/mfdef.h
# Things that the mailer does not need to send the milter:
SMFIP_NOCONNECT	= 0x01
SMFIP_NOHELO	= 0x02
SMFIP_NOMAIL	= 0x04
SMFIP_NORCPT	= 0x08
SMFIP_NOBODY	= 0x10
SMFIP_NOHDRS	= 0x20
SMFIP_NOEOH	= 0x40

# Acceptable response commands/codes to return to sendmail (with accompanying
# command data).  From sendmail's include/libmilter/mfdef.h
SMFIR_ADDRCPT	= '+' # 'Add recipient'
SMFIR_DELRCPT	= '-' # 'Delete recipient'
SMFIR_ACCEPT	= 'a' # 'Accept recipient'
SMFIR_REPLBODY	= 'b' # 'replace body (chunk)'
SMFIR_CONTINUE	= 'c' # 'Continue'
SMFIR_DISCARD	= 'd' # 'discard'
SMFIR_CONN_FAIL = 'f' # 'cause a connection failure'
SMFIR_ADDHEADER = 'h' # 'add header'
SMFIR_INSHEADER = 'i' # 'insert header'
SMFIR_CHGHEADER = 'm' # 'change header'
SMFIR_PROGRESS	= 'p' # 'progress'
SMFIR_QUARANTINE = 'q' # quarantine
SMFIR_REJECT	= 'r' # 'reject'
SMFIR_SETSENDER = 's' # may be v3 only
SMFIR_TEMPFAIL	= 't' # 'tempfail'
SMFIR_REPLYCODE = 'y' # 'reply code'
