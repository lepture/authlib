# -*- coding: utf-8 -*-
"""
    authlib.specs.rfc5849.signature
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    This module represents a direct implementation of `section 3.4`_ of the spec.

    .. _`section 3.4`: http://tools.ietf.org/html/rfc5849#section-3.4
"""

from __future__ import absolute_import, unicode_literals

import binascii
import hashlib
import hmac
from authlib.common.urls import urlparse, url_decode, extract_params
from authlib.common.encoding import to_unicode, to_bytes
from .util import (
    escape, unescape,
    safe_string_equals,
    parse_authorization_header,
)

SIGNATURE_HMAC_SHA1 = "HMAC-SHA1"
SIGNATURE_RSA_SHA1 = "RSA-SHA1"
SIGNATURE_PLAINTEXT = "PLAINTEXT"

SIGNATURE_TYPE_HEADER = 'HEADER'
SIGNATURE_TYPE_QUERY = 'QUERY'
SIGNATURE_TYPE_BODY = 'BODY'


def construct_base_string(method, uri, normalized_parameters):
    """**String Construction**
    Per `section 3.4.1.1`_ of the spec.

    For example, the HTTP request::

        POST /request?b5=%3D%253D&a3=a&c%40=&a2=r%20b HTTP/1.1
        Host: example.com
        Content-Type: application/x-www-form-urlencoded
        Authorization: OAuth realm="Example",
            oauth_consumer_key="9djdj82h48djs9d2",
            oauth_token="kkk9d7dh3k39sjv7",
            oauth_signature_method="HMAC-SHA1",
            oauth_timestamp="137131201",
            oauth_nonce="7d8f3e4a",
            oauth_signature="bYT5CMsGcbgUdFHObYMEfcx6bsw%3D"

        c2&a3=2+q

    is represented by the following signature base string (line breaks
    are for display purposes only)::

        POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q
        %26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_
        key%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a%26oauth_signature_m
        ethod%3DHMAC-SHA1%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk
        9d7dh3k39sjv7

    .. _`section 3.4.1.1`: http://tools.ietf.org/html/rfc5849#section-3.4.1.1
    """
    params = [
        escape(method.upper()),
        escape(uri),
        escape(normalized_parameters),
    ]
    return '&'.join(params)


def normalize_base_string_uri(uri, host=None):
    """**Base String URI**
    Per `section 3.4.1.2`_ of the spec.

    For example, the HTTP request::

        GET /r%20v/X?id=123 HTTP/1.1
        Host: EXAMPLE.COM:80

    is represented by the base string URI: "http://example.com/r%20v/X".

    In another example, the HTTPS request::

        GET /?q=1 HTTP/1.1
        Host: www.example.net:8080

    is represented by the base string URI: "https://www.example.net:8080/".

    .. _`section 3.4.1.2`: http://tools.ietf.org/html/rfc5849#section-3.4.1.2

    The host argument overrides the netloc part of the uri argument.
    """
    uri = to_unicode(uri)
    scheme, netloc, path, params, query, fragment = urlparse.urlparse(uri)

    # The scheme, authority, and path of the request resource URI `RFC3986`
    # are included by constructing an "http" or "https" URI representing
    # the request resource (without the query or fragment) as follows:
    #
    # .. _`RFC3986`: http://tools.ietf.org/html/rfc3986

    if not scheme or not netloc:
        raise ValueError('uri must include a scheme and netloc')

    # Per `RFC 2616 section 5.1.2`_:
    #
    # Note that the absolute path cannot be empty; if none is present in
    # the original URI, it MUST be given as "/" (the server root).
    #
    # .. _`RFC 2616 section 5.1.2`: http://tools.ietf.org/html/rfc2616#section-5.1.2
    if not path:
        path = '/'

    # 1.  The scheme and host MUST be in lowercase.
    scheme = scheme.lower()
    netloc = netloc.lower()

    # 2.  The host and port values MUST match the content of the HTTP
    #     request "Host" header field.
    if host is not None:
        netloc = host.lower()

    # 3.  The port MUST be included if it is not the default port for the
    #     scheme, and MUST be excluded if it is the default.  Specifically,
    #     the port MUST be excluded when making an HTTP request `RFC2616`_
    #     to port 80 or when making an HTTPS request `RFC2818`_ to port 443.
    #     All other non-default port numbers MUST be included.
    #
    # .. _`RFC2616`: http://tools.ietf.org/html/rfc2616
    # .. _`RFC2818`: http://tools.ietf.org/html/rfc2818
    default_ports = (
        ('http', '80'),
        ('https', '443'),
    )
    if ':' in netloc:
        host, port = netloc.split(':', 1)
        if (scheme, port) in default_ports:
            netloc = host

    return urlparse.urlunparse((scheme, netloc, path, params, '', ''))


# ** Request Parameters **
#
#    Per `section 3.4.1.3`_ of the spec.
#
#    In order to guarantee a consistent and reproducible representation of
#    the request parameters, the parameters are collected and decoded to
#    their original decoded form.  They are then sorted and encoded in a
#    particular manner that is often different from their original
#    encoding scheme, and concatenated into a single string.
#
# .. _`section 3.4.1.3`: http://tools.ietf.org/html/rfc5849#section-3.4.1.3


def collect_parameters(uri_query='', body=None, headers=None,
                       exclude_oauth_signature=True, with_realm=False):
    """**Parameter Sources**

    Parameters starting with `oauth_` will be unescaped.

    Body parameters must be supplied as a dict, a list of 2-tuples, or a
    formencoded query string.

    Headers must be supplied as a dict.

    Per `section 3.4.1.3.1`_ of the spec.

    For example, the HTTP request::

        POST /request?b5=%3D%253D&a3=a&c%40=&a2=r%20b HTTP/1.1
        Host: example.com
        Content-Type: application/x-www-form-urlencoded
        Authorization: OAuth realm="Example",
            oauth_consumer_key="9djdj82h48djs9d2",
            oauth_token="kkk9d7dh3k39sjv7",
            oauth_signature_method="HMAC-SHA1",
            oauth_timestamp="137131201",
            oauth_nonce="7d8f3e4a",
            oauth_signature="djosJKDKJSD8743243%2Fjdk33klY%3D"

        c2&a3=2+q

    contains the following (fully decoded) parameters used in the
    signature base sting::

        +------------------------+------------------+
        |          Name          |       Value      |
        +------------------------+------------------+
        |           b5           |       =%3D       |
        |           a3           |         a        |
        |           c@           |                  |
        |           a2           |        r b       |
        |   oauth_consumer_key   | 9djdj82h48djs9d2 |
        |       oauth_token      | kkk9d7dh3k39sjv7 |
        | oauth_signature_method |     HMAC-SHA1    |
        |     oauth_timestamp    |     137131201    |
        |       oauth_nonce      |     7d8f3e4a     |
        |           c2           |                  |
        |           a3           |        2 q       |
        +------------------------+------------------+

    Note that the value of "b5" is "=%3D" and not "==".  Both "c@" and
    "c2" have empty values.  While the encoding rules specified in this
    specification for the purpose of constructing the signature base
    string exclude the use of a "+" character (ASCII code 43) to
    represent an encoded space character (ASCII code 32), this practice
    is widely used in "application/x-www-form-urlencoded" encoded values,
    and MUST be properly decoded, as demonstrated by one of the "a3"
    parameter instances (the "a3" parameter is used twice in this
    request).

    .. _`section 3.4.1.3.1`: http://tools.ietf.org/html/rfc5849#section-3.4.1.3.1
    """
    params = []

    # The parameters from the following sources are collected into a single
    # list of name/value pairs:

    # *  The query component of the HTTP request URI as defined by
    #    `RFC3986, Section 3.4`_.  The query component is parsed into a list
    #    of name/value pairs by treating it as an
    #    "application/x-www-form-urlencoded" string, separating the names
    #    and values and decoding them as defined by
    #    `W3C.REC-html40-19980424`_, Section 17.13.4.
    #
    # .. _`RFC3986, Section 3.4`: http://tools.ietf.org/html/rfc3986#section-3.4
    # .. _`W3C.REC-html40-19980424`: http://tools.ietf.org/html/rfc5849#ref-W3C.REC-html40-19980424
    if uri_query:
        params.extend(url_decode(uri_query))

    # *  The OAuth HTTP "Authorization" header field (`Section 3.5.1`_) if
    #    present. The header's content is parsed into a list of name/value
    #    pairs excluding the "realm" parameter if present.  The parameter
    #    values are decoded as defined by `Section 3.5.1`_.
    #
    # .. _`Section 3.5.1`: http://tools.ietf.org/html/rfc5849#section-3.5.1
    if headers:
        for k, v in headers.items():
            if k.lower() == 'authorization' and v is not None:
                params.extend(parse_authorization_header(v, with_realm))

    # *  The HTTP request entity-body, but only if all of the following
    #    conditions are met:
    #     *  The entity-body is single-part.
    #
    #     *  The entity-body follows the encoding requirements of the
    #        "application/x-www-form-urlencoded" content-type as defined by
    #        `W3C.REC-html40-19980424`_.

    #     *  The HTTP request entity-header includes the "Content-Type"
    #        header field set to "application/x-www-form-urlencoded".
    #
    # .._`W3C.REC-html40-19980424`: http://tools.ietf.org/html/rfc5849#ref-W3C.REC-html40-19980424

    if body:
        params.extend(extract_params(body))

    # ensure all oauth params are unescaped
    unescaped_params = []
    for k, v in params:
        # The "oauth_signature" parameter MUST be excluded from the signature
        if exclude_oauth_signature and k == 'oauth_signature':
            continue

        if k.startswith('oauth_'):
            v = unescape(v)
        unescaped_params.append((k, v))

    return unescaped_params


def normalize_parameters(params):
    """**Parameters Normalization**
    Per `section 3.4.1.3.2`_ of the spec.

    For example, the list of parameters from the previous section would
    be normalized as follows:

    Encoded::

    +------------------------+------------------+
    |          Name          |       Value      |
    +------------------------+------------------+
    |           b5           |     %3D%253D     |
    |           a3           |         a        |
    |          c%40          |                  |
    |           a2           |       r%20b      |
    |   oauth_consumer_key   | 9djdj82h48djs9d2 |
    |       oauth_token      | kkk9d7dh3k39sjv7 |
    | oauth_signature_method |     HMAC-SHA1    |
    |     oauth_timestamp    |     137131201    |
    |       oauth_nonce      |     7d8f3e4a     |
    |           c2           |                  |
    |           a3           |       2%20q      |
    +------------------------+------------------+

    Sorted::

    +------------------------+------------------+
    |          Name          |       Value      |
    +------------------------+------------------+
    |           a2           |       r%20b      |
    |           a3           |       2%20q      |
    |           a3           |         a        |
    |           b5           |     %3D%253D     |
    |          c%40          |                  |
    |           c2           |                  |
    |   oauth_consumer_key   | 9djdj82h48djs9d2 |
    |       oauth_nonce      |     7d8f3e4a     |
    | oauth_signature_method |     HMAC-SHA1    |
    |     oauth_timestamp    |     137131201    |
    |       oauth_token      | kkk9d7dh3k39sjv7 |
    +------------------------+------------------+

    Concatenated Pairs::

    +-------------------------------------+
    |              Name=Value             |
    +-------------------------------------+
    |               a2=r%20b              |
    |               a3=2%20q              |
    |                 a3=a                |
    |             b5=%3D%253D             |
    |                c%40=                |
    |                 c2=                 |
    | oauth_consumer_key=9djdj82h48djs9d2 |
    |         oauth_nonce=7d8f3e4a        |
    |   oauth_signature_method=HMAC-SHA1  |
    |      oauth_timestamp=137131201      |
    |     oauth_token=kkk9d7dh3k39sjv7    |
    +-------------------------------------+

    and concatenated together into a single string (line breaks are for
    display purposes only)::

        a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9dj
        dj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1
        &oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7

    .. _`section 3.4.1.3.2`: http://tools.ietf.org/html/rfc5849#section-3.4.1.3.2
    """

    # The parameters collected in `Section 3.4.1.3`_ are normalized into a
    # single string as follows:
    #
    # .. _`Section 3.4.1.3`: http://tools.ietf.org/html/rfc5849#section-3.4.1.3

    # 1.  First, the name and value of each parameter are encoded
    #     (`Section 3.6`_).
    #
    # .. _`Section 3.6`: http://tools.ietf.org/html/rfc5849#section-3.6
    key_values = [(escape(k), escape(v)) for k, v in params]

    # 2.  The parameters are sorted by name, using ascending byte value
    #     ordering.  If two or more parameters share the same name, they
    #     are sorted by their value.
    key_values.sort()

    # 3.  The name of each parameter is concatenated to its corresponding
    #     value using an "=" character (ASCII code 61) as a separator, even
    #     if the value is empty.
    parameter_parts = ['{0}={1}'.format(k, v) for k, v in key_values]

    # 4.  The sorted name/value pairs are concatenated together into a
    #     single string by using an "&" character (ASCII code 38) as
    #     separator.
    return '&'.join(parameter_parts)


def base_string_from_request(method, uri, body, headers):
    """Construct base string from a HTTP request."""
    collected_params = collect_parameters(
        uri_query=urlparse.urlparse(uri).query,
        body=body,
        headers=headers
    )

    normalized_params = normalize_parameters(collected_params)
    normalized_uri = normalize_base_string_uri(
        uri, headers.get('Host', None)
    )

    return construct_base_string(method, normalized_uri, normalized_params)


def sign_hmac_sha1(base_string, client_secret, resource_owner_secret):
    """**HMAC-SHA1**

    The "HMAC-SHA1" signature method uses the HMAC-SHA1 signature
    algorithm as defined in `RFC2104`_::

        digest = HMAC-SHA1 (key, text)

    Per `section 3.4.2`_ of the spec.

    .. _`RFC2104`: http://tools.ietf.org/html/rfc2104
    .. _`section 3.4.2`: http://tools.ietf.org/html/rfc5849#section-3.4.2
    """

    # The HMAC-SHA1 function variables are used in following way:

    # text is set to the value of the signature base string from
    # `Section 3.4.1.1`_.
    #
    # .. _`Section 3.4.1.1`: http://tools.ietf.org/html/rfc5849#section-3.4.1.1
    text = base_string

    # key is set to the concatenated values of:
    # 1.  The client shared-secret, after being encoded (`Section 3.6`_).
    #
    # .. _`Section 3.6`: http://tools.ietf.org/html/rfc5849#section-3.6
    key = escape(client_secret or '')

    # 2.  An "&" character (ASCII code 38), which MUST be included
    #     even when either secret is empty.
    key += '&'

    # 3.  The token shared-secret, after being encoded (`Section 3.6`_).
    #
    # .. _`Section 3.6`: http://tools.ietf.org/html/rfc5849#section-3.6
    key += escape(resource_owner_secret or '')

    signature = hmac.new(to_bytes(key), to_bytes(text), hashlib.sha1)

    # digest  is used to set the value of the "oauth_signature" protocol
    #         parameter, after the result octet string is base64-encoded
    #         per `RFC2045, Section 6.8`.
    #
    # .. _`RFC2045, Section 6.8`: http://tools.ietf.org/html/rfc2045#section-6.8
    sig = binascii.b2a_base64(signature.digest())[:-1]
    return to_unicode(sig)


_jwtrs1 = None


def _jwt_rs1_signing_algorithm():
    # jwt has some nice pycrypto/cryptography abstractions
    global _jwtrs1
    if _jwtrs1 is None:
        import jwt.algorithms as jwtalgo
        _jwtrs1 = jwtalgo.RSAAlgorithm(jwtalgo.hashes.SHA1)
    return _jwtrs1


def sign_rsa_sha1(base_string, rsa_private_key):
    """**RSA-SHA1**

    Per `section 3.4.3`_ of the spec.

    The "RSA-SHA1" signature method uses the RSASSA-PKCS1-v1_5 signature
    algorithm as defined in `RFC3447, Section 8.2`_ (also known as
    PKCS#1), using SHA-1 as the hash function for EMSA-PKCS1-v1_5.  To
    use this method, the client MUST have established client credentials
    with the server that included its RSA public key (in a manner that is
    beyond the scope of this specification).

    .. _`section 3.4.3`: http://tools.ietf.org/html/rfc5849#section-3.4.3
    .. _`RFC3447, Section 8.2`: http://tools.ietf.org/html/rfc3447#section-8.2

    """
    base_string = to_bytes(base_string)
    alg = _jwt_rs1_signing_algorithm()
    key = alg.prepare_key(to_unicode(rsa_private_key))
    s = alg.sign(base_string, key)
    sig = binascii.b2a_base64(s)[:-1]
    return to_unicode(sig)


def sign_plaintext(client_secret, resource_owner_secret):
    """Sign a request using plaintext.

    Per `section 3.4.4`_ of the spec.

    The "PLAINTEXT" method does not employ a signature algorithm.  It
    MUST be used with a transport-layer mechanism such as TLS or SSL (or
    sent over a secure channel with equivalent protections).  It does not
    utilize the signature base string or the "oauth_timestamp" and
    "oauth_nonce" parameters.

    .. _`section 3.4.4`: http://tools.ietf.org/html/rfc5849#section-3.4.4

    """

    # The "oauth_signature" protocol parameter is set to the concatenated
    # value of:

    # 1.  The client shared-secret, after being encoded (`Section 3.6`_).
    #
    # .. _`Section 3.6`: http://tools.ietf.org/html/rfc5849#section-3.6
    signature = escape(client_secret or '')

    # 2.  An "&" character (ASCII code 38), which MUST be included even
    #     when either secret is empty.
    signature += '&'

    # 3.  The token shared-secret, after being encoded (`Section 3.6`_).
    #
    # .. _`Section 3.6`: http://tools.ietf.org/html/rfc5849#section-3.6
    signature += escape(resource_owner_secret or '')

    return signature


def verify_hmac_sha1(signature, http_method, uri, params,
                     client_secret=None, resource_owner_secret=None):
    """Verify a HMAC-SHA1 signature.

    Per `section 3.4`_ of the spec.

    .. _`section 3.4`: http://tools.ietf.org/html/rfc5849#section-3.4

    To satisfy `RFC2616 section 5.2`_ item 1, the request argument's uri
    attribute MUST be an absolute URI whose netloc part identifies the
    origin server or gateway on which the resource resides. Any Host
    item of the request argument's headers dict attribute will be
    ignored.

    .. _`RFC2616 section 5.2`: http://tools.ietf.org/html/rfc2616#section-5.2

    """
    uri = normalize_base_string_uri(uri)
    params = normalize_parameters(params)
    base_string = construct_base_string(http_method, uri, params)
    sig = sign_hmac_sha1(base_string, client_secret, resource_owner_secret)
    return safe_string_equals(sig, signature)


def verify_rsa_sha1(signature, http_method, uri, params, rsa_public_key):
    """Verify a RSASSA-PKCS #1 v1.5 base64 encoded signature.

    Per `section 3.4.3`_ of the spec.

    Note this method requires the jwt and cryptography libraries.

    .. _`section 3.4.3`: http://tools.ietf.org/html/rfc5849#section-3.4.3

    To satisfy `RFC2616 section 5.2`_ item 1, the request argument's uri
    attribute MUST be an absolute URI whose netloc part identifies the
    origin server or gateway on which the resource resides. Any Host
    item of the request argument's headers dict attribute will be
    ignored.

    .. _`RFC2616 section 5.2`: http://tools.ietf.org/html/rfc2616#section-5.2
    """
    uri = normalize_base_string_uri(uri)
    norm_params = normalize_parameters(params)
    text = construct_base_string(http_method, uri, norm_params)

    alg = _jwt_rs1_signing_algorithm()
    key = alg.prepare_key(to_unicode(rsa_public_key))

    sig = binascii.a2b_base64(to_bytes(signature))
    return alg.verify(to_bytes(text), key, sig)


def verify_plaintext(signature, client_secret=None, resource_owner_secret=None):
    """Verify a PLAINTEXT signature.

    Per `section 3.4`_ of the spec.

    .. _`section 3.4`: http://tools.ietf.org/html/rfc5849#section-3.4
    """
    sig = sign_plaintext(client_secret, resource_owner_secret)
    return safe_string_equals(sig, signature)
