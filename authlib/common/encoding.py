import base64
import struct
from requests.compat import is_py2

if is_py2:
    unicode_type = unicode
    byte_type = str
else:
    unicode_type = str
    byte_type = bytes


def to_bytes(x, charset='utf-8', errors='strict'):
    if x is None:
        return None
    if isinstance(x, byte_type):
        return x
    if isinstance(x, unicode_type):
        return x.encode(charset, errors)
    if isinstance(x, (int, float)):
        return str(x).encode(charset, errors)
    return byte_type(x)


def to_unicode(x, charset='utf-8', errors='strict', allow_none_charset=False):
    if x is None:
        return None
    if not isinstance(x, byte_type):
        return unicode_type(x)
    if charset is None and allow_none_charset:
        return x
    return x.decode(charset, errors)


def urlsafe_b64decode(s):
    s += b'=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def urlsafe_b64encode(s):
    return base64.urlsafe_b64encode(s).rstrip(b'=')


_int64_struct = struct.Struct('>Q')
_int_to_bytes = _int64_struct.pack
_bytes_to_int = _int64_struct.unpack


def int_to_bytes(num, length=None):
    if num == 0:
        s = b'\x00'
    else:
        s = _int_to_bytes(num).lstrip(b'\x00')
    if length:
        if length < len(s):
            raise TypeError('Odd-length string')
        return b'\x00' * (length - len(s)) + s
    return s


def bytes_to_int(byte_str):
    return _bytes_to_int(byte_str.rjust(8, b'\x00'))[0]


def base64_to_int(s):
    data = urlsafe_b64decode(to_bytes(s, charset='ascii'))
    buf = struct.unpack('%sB' % len(data), data)
    return int(''.join(["%02x" % byte for byte in buf]), 16)


def int_to_base64(num):
    if num < 0:
        raise ValueError('Must be a positive integer')
    return urlsafe_b64encode(int_to_bytes(num))
