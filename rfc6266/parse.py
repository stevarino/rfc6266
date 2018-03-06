from __future__ import absolute_import

try:
    import lepl
except ImportError:
    lepl = None
from collections import namedtuple
from urlparse import urlsplit
import os.path
import posixpath
import re

from .common import *

LangTagged = namedtuple('LangTagged', 'string langtag')

class ContentDisposition(object):
    """
    Records various indications and hints about content disposition.

    These can be used to know if a file should be downloaded or
    displayed directly, and to hint what filename it should have
    in the download case.
    """

    def __init__(self, disposition='inline', assocs=None, location=None):
        """This constructor is used internally after parsing the header.

        Instances should generally be created from a factory
        function, such as parse_headers and its variants.
        """
        assert lepl, "lepl is not installed"
        self.disposition = disposition
        self.location = location
        if assocs is None:
            self.assocs = {}
        else:
            # XXX Check that parameters aren't repeated
            self.assocs = dict((key.lower(), val) for (key, val) in assocs)

    @property
    def filename_unsafe(self):
        """The filename from the Content-Disposition header.

        If a location was passed at instanciation, the basename
        from that may be used as a fallback. Otherwise, this may
        be the None value.

        On safety:
            This property records the intent of the sender.

            You shouldn't use this sender-controlled value as a filesystem
        path, it can be insecure. Serving files with this filename can be
        dangerous as well, due to a certain browser using the part after the
        dot for mime-sniffing.
        Saving it to a database is fine by itself though.
        """

        if 'filename*' in self.assocs:
            return self.assocs['filename*'].string
        elif 'filename' in self.assocs:
            # XXX Reject non-ascii (parsed via qdtext) here?
            return self.assocs['filename']
        elif self.location is not None:
            return posixpath.basename(self.location_path.rstrip('/'))

    @property
    def location_path(self):
        if self.location:
            return percent_decode(
                urlsplit(self.location, scheme='http').path,
                encoding='utf-8')

    def filename_sanitized(self, extension, default_filename='file'):
        """Returns a filename that is safer to use on the filesystem.

        The filename will not contain a slash (nor the path separator
        for the current platform, if different), it will not
        start with a dot, and it will have the expected extension.

        No guarantees that makes it "safe enough".
        No effort is made to remove special characters;
        using this value blindly might overwrite existing files, etc.
        """

        assert extension
        assert extension[0] != '.'
        assert default_filename
        assert '.' not in default_filename
        extension = '.' + extension

        fname = self.filename_unsafe
        if fname is None:
            fname = default_filename
        fname = posixpath.basename(fname)
        fname = os.path.basename(fname)
        fname = fname.lstrip('.')
        if not fname:
            fname = default_filename
        if not fname.endswith(extension):
            fname = fname + extension
        return fname

    @property
    def is_inline(self):
        """If this property is true, the file should be handled inline.

        Otherwise, and unless your application supports other dispositions
        than the standard inline and attachment, it should be handled
        as an attachment.
        """

        return self.disposition.lower() == 'inline'

    def __repr__(self):
        return 'ContentDisposition(%r, %r, %r)' % (
            self.disposition, self.assocs, self.location)


def ensure_charset(text, encoding):
    if isinstance(text, bytes):
        return text.decode(encoding)
    else:
        assert fits_inside_codec(text, encoding)
        return text


def parse_headers(content_disposition, location=None, relaxed=False):
    """Build a ContentDisposition from header values.
    """
    assert lepl, "lepl is not installed"

    LOGGER.debug(
        'Content-Disposition %r, Location %r', content_disposition, location)

    if content_disposition is None:
        return ContentDisposition(location=location)

    # Both alternatives seem valid.
    if False:
        # Require content_disposition to be ascii bytes (0-127),
        # or characters in the ascii range
        content_disposition = ensure_charset(content_disposition, 'ascii')
    else:
        # We allow non-ascii here (it will only be parsed inside of
        # qdtext, and rejected by the grammar if it appears in
        # other places), although parsing it can be ambiguous.
        # Parsing it ensures that a non-ambiguous filename* value
        # won't get dismissed because of an unrelated ambiguity
        # in the filename parameter. But it does mean we occasionally
        # give less-than-certain values for some legacy senders.
        content_disposition = ensure_charset(content_disposition, 'iso-8859-1')

    # Check the caller already did LWS-folding (normally done
    # when separating header names and values; RFC 2616 section 2.2
    # says it should be done before interpretation at any rate).
    # Hopefully space still means what it should in iso-8859-1.
    # This check is a bit stronger that LWS folding, it will
    # remove CR and LF even if they aren't part of a CRLF.
    # However http doesn't allow isolated CR and LF in headers outside
    # of LWS.

    if relaxed:
        # Relaxed has two effects (so far):
        # the grammar allows a final ';' in the header;
        # we do LWS-folding, and possibly normalise other broken
        # whitespace, instead of rejecting non-lws-safe text.
        # XXX Would prefer to accept only the quoted whitespace
        # case, rather than normalising everything.
        content_disposition = normalize_ws(content_disposition)
        parser = content_disposition_value_relaxed
    else:
        # Turns out this is occasionally broken: two spaces inside
        # a quoted_string's qdtext. Firefox and Chrome save the two spaces.
        if not is_lws_safe(content_disposition):
            raise ValueError(
                content_disposition, 'Contains nonstandard whitespace')

        parser = content_disposition_value

    try:
        parsed = parser.parse(content_disposition)
    except lepl.FullFirstMatchException:
        return ContentDisposition(location=location)
    return ContentDisposition(
        disposition=parsed[0], assocs=parsed[1:], location=location)


def parse_httplib2_response(response, **kwargs):
    """Build a ContentDisposition from an httplib2 response.
    """

    return parse_headers(
        response.get('content-disposition'),
        response['content-location'], **kwargs)


def parse_requests_response(response, **kwargs):
    """Build a ContentDisposition from a requests (PyPI) response.
    """

    return parse_headers(
        response.headers.get('content-disposition'), response.url, **kwargs)


def parse_ext_value(val):
    charset = val[0]
    if len(val) == 3:
        charset, langtag, coded = val
    else:
        charset, coded = val
        langtag = None
    if not PY3K and isinstance(coded, unicode):
        coded = coded.encode('ascii')
    decoded = percent_decode(coded, encoding=charset)
    return LangTagged(decoded, langtag)


# Currently LEPL doesn't handle case-insensivitity:
# https://groups.google.com/group/lepl/browse_thread/thread/68e7b136038772ca
def CaseInsensitiveLiteral(lit):
    return lepl.Regexp('(?i)' + re.escape(lit))

if lepl:
    # To debug, wrap in this block:
    #with TraceVariables():

    # Definitions from https://tools.ietf.org/html/rfc2616#section-2.2
    # token was redefined from attr_chars to avoid using AnyBut,
    # which might include non-ascii octets.
    token = lepl.Any(token_chars)[1:, ...]


    # RFC 2616 says some linear whitespace (LWS) is in fact allowed in text
    # and qdtext; however it also mentions folding that whitespace into
    # a single SP (which isn't in CTL) before interpretation.
    # Assume the caller already that folding when parsing headers.

    # NOTE: qdtext also allows non-ascii, which we choose to parse
    # as ISO-8859-1; rejecting it entirely would also be permitted.
    # Some broken browsers attempt encoding-sniffing, which is broken
    # because the spec only allows iso, and because encoding-sniffing
    # can mangle valid values.
    # Everything else in this grammar (including RFC 5987 ext values)
    # is in an ascii-safe encoding.
    # Because of this, this is the only character class to use AnyBut,
    # and all the others are defined with Any.
    qdtext = lepl.AnyBut('"' + ctl_chars)

    char = lepl.Any(''.join(chr(i) for i in xrange(128)))  # ascii range: 0-127

    quoted_pair = lepl.Drop('\\') + char
    quoted_string = lepl.Drop('"') & (quoted_pair | qdtext)[:, ...] & lepl.Drop('"')

    value = token | quoted_string

    # Other charsets are forbidden, the spec reserves them
    # for future evolutions.
    charset = (CaseInsensitiveLiteral('UTF-8')
            | CaseInsensitiveLiteral('ISO-8859-1'))

    # XXX See RFC 5646 for the correct definition
    language = token

    attr_char = lepl.Any(attr_chars)
    hexdig = lepl.Any(hexdigits)
    pct_encoded = '%' + hexdig + hexdig
    value_chars = (pct_encoded | attr_char)[...]
    ext_value = (
        charset & lepl.Drop("'") & lepl.Optional(language) & lepl.Drop("'")
        & value_chars) > parse_ext_value
    ext_token = token + '*'
    noext_token = ~lepl.Lookahead(ext_token) & token

    # Adapted from https://tools.ietf.org/html/rfc6266
    # Mostly this was simplified to fold filename / filename*
    # into the normal handling of ext_token / noext_token
    with lepl.DroppedSpace():
        disposition_parm = (
            (ext_token & lepl.Drop('=') & ext_value)
            | (noext_token & lepl.Drop('=') & value)) > tuple
        disposition_type = (
            CaseInsensitiveLiteral('inline')
            | CaseInsensitiveLiteral('attachment')
            | token)
        content_disposition_value = (
            disposition_type & lepl.Star(lepl.Drop(';') & disposition_parm))

        # Allows nonconformant final semicolon
        # I've seen it in the wild, and browsers accept it
        # http://greenbytes.de/tech/tc2231/#attwithasciifilenamenqs
        content_disposition_value_relaxed = (
            content_disposition_value & lepl.Optional(lepl.Drop(';')))

