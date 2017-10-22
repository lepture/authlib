"""
    authlib.util.urls
    ~~~~~~~~~~~~~~~~~

    Wrapper functions for URL encoding and decoding.
"""

import re
try:
    from urllib import quote as _quote
    from urllib import unquote as _unquote
    from urllib import urlencode as _urlencode
except ImportError:
    from urllib.parse import quote as _quote
    from urllib.parse import unquote as _unquote
    from urllib.parse import urlencode as _urlencode
try:
    import urlparse
except ImportError:
    import urllib.parse as urlparse

from .encoding import to_unicode, to_bytes

always_safe = (
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    'abcdefghijklmnopqrstuvwxyz'
    '0123456789_.-'
)
urlencoded = set(always_safe) | set('=&;:%+~,*@!()/?')
INVALID_HEX_PATTERN = re.compile(r'%[^0-9A-Fa-f]|%[0-9A-Fa-f][^0-9A-Fa-f]')


def url_encode(params):
    encoded = []
    for k, v in params:
        encoded.append((to_bytes(k), to_bytes(v)))
    return to_unicode(_urlencode(encoded))


def url_decode(query):
    """Decode a query string in x-www-form-urlencoded format into a sequence
    of two-element tuples.

    Unlike urlparse.parse_qsl(..., strict_parsing=True) urldecode will enforce
    correct formatting of the query string by validation. If validation fails
    a ValueError will be raised. urllib.parse_qsl will only raise errors if
    any of name-value pairs omits the equals sign.
    """
    # Check if query contains invalid characters
    if query and not set(query) <= urlencoded:
        error = ("Error trying to decode a non urlencoded string. "
                 "Found invalid characters: %s "
                 "in the string: '%s'. "
                 "Please ensure the request/response body is "
                 "x-www-form-urlencoded.")
        raise ValueError(error % (set(query) - urlencoded, query))

    # Check for correctly hex encoded values using a regular expression
    # All encoded values begin with % followed by two hex characters
    # correct = %00, %A0, %0A, %FF
    # invalid = %G0, %5H, %PO
    if INVALID_HEX_PATTERN.search(query):
        raise ValueError('Invalid hex encoding in query string.')

    # We encode to utf-8 prior to parsing because parse_qsl behaves
    # differently on unicode input in python 2 and 3.
    # Python 2.7
    # >>> urlparse.parse_qsl(u'%E5%95%A6%E5%95%A6')
    # u'\xe5\x95\xa6\xe5\x95\xa6'
    # Python 2.7, non unicode input gives the same
    # >>> urlparse.parse_qsl('%E5%95%A6%E5%95%A6')
    # '\xe5\x95\xa6\xe5\x95\xa6'
    # but now we can decode it to unicode
    # >>> urlparse.parse_qsl('%E5%95%A6%E5%95%A6').decode('utf-8')
    # u'\u5566\u5566'
    # Python 3.3 however
    # >>> urllib.parse.parse_qsl(u'%E5%95%A6%E5%95%A6')
    # u'\u5566\u5566'

    query = to_bytes(query)
    # We want to allow queries such as "c2" whereas urlparse.parse_qsl
    # with the strict_parsing flag will not.
    params = urlparse.parse_qsl(query, keep_blank_values=True)

    # unicode all the things
    decoded = []
    for k, v in params:
        decoded.append((to_unicode(k), to_unicode(v)))
    return decoded
