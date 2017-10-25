from authlib.common.urls import (
    quote, unquote,
    parse_http_list, parse_keqv_list,
)


def escape(s):
    return quote(s, safe=b'~')


def unescape(s):
    return unquote(s)


def safe_string_equals(a, b):
    """ Near-constant time string comparison.

    Used in order to avoid timing attacks on sensitive information such
    as secret keys during request verification (`rootLabs`_).

    .. _`rootLabs`: http://rdist.root.org/2010/01/07/timing-independent-array-comparison/

    """
    if len(a) != len(b):
        return False

    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    return result == 0


def parse_authorization_header(authorization_header, with_realm=False):
    """Parse an OAuth authorization header into a list of 2-tuples"""
    auth_scheme = 'OAuth '.lower()
    if authorization_header.lower().startswith(auth_scheme):
        items = parse_http_list(authorization_header[len(auth_scheme):])
        try:
            params = []
            for k, v in parse_keqv_list(items).items():
                if k == 'realm':
                    if with_realm:
                        params.append((k, v))
                else:
                    params.append((k, v))
            return params
        except (IndexError, ValueError):
            pass
    raise ValueError('Malformed authorization header')
