from urllib import quote, unquote
from string import hexdigits, ascii_letters, digits

import logging
import sys
import re

LOGGER = logging.getLogger('rfc6266')
try:
    LOGGER.addHandler(logging.NullHandler())
except AttributeError:
    pass

PY3K = sys.version_info >= (3,)

if PY3K:
    # XXX Both implementations allow stray %
    def percent_encode(string, safe, encoding):
        return quote(string, safe, encoding, errors='strict')

    def percent_decode(string, encoding):
        # unquote doesn't default to strict, fix that
        return unquote(string, encoding, errors='strict')
else:
    def percent_encode(string, **kwargs):
        encoding = kwargs.pop('encoding')
        return quote(string.encode(encoding), **kwargs)

    def percent_decode(string, **kwargs):
        encoding = kwargs.pop('encoding')
        return unquote(string, **kwargs).decode(encoding)


# RFC 2616
separator_chars = "()<>@,;:\\\"/[]?={} \t"
ctl_chars = ''.join(chr(i) for i in xrange(32)) + chr(127)
nontoken_chars = separator_chars + ctl_chars

# RFC 5987
attr_chars_nonalnum = '!#$&+-.^_`|~'
attr_chars = ascii_letters + digits + attr_chars_nonalnum

# RFC 5987 gives this alternative construction of the token character class
token_chars = attr_chars + "*'%"


def is_token_char(ch):
    # Must be ascii, and neither a control char nor a separator char
    asciicode = ord(ch)
    # < 128 means ascii, exclude control chars at 0-31 and 127,
    # exclude separator characters.
    return 31 < asciicode < 127 and ch not in separator_chars


def usesonlycharsfrom(candidate, chars):
    # Found that shortcut in urllib.quote
    return candidate.rstrip(chars) == ''


def is_token(candidate):
    #return usesonlycharsfrom(candidate, token_chars)
    return all(is_token_char(ch) for ch in candidate)


def is_ascii(text):
    return all(ord(ch) < 128 for ch in text)


def fits_inside_codec(text, codec):
    try:
        text.encode(codec)
    except UnicodeEncodeError:
        return False
    else:
        return True


def is_lws_safe(text):
    return normalize_ws(text) == text


def normalize_ws(text):
    return ' '.join(text.split())


def qd_quote(text):
    return text.replace('\\', '\\\\').replace('"', '\\"')

