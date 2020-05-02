import sys
import json
import base64
import struct

is_py2 = sys.version_info[0] == 2

if is_py2:
    unicode_type = unicode  # noqa: F821
    byte_type = str
    text_types = (unicode, str)  # noqa: F821
else:
    unicode_type = str
    byte_type = bytes
    text_types = (str, )


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


def to_unicode(x, charset='utf-8', errors='strict'):
    if x is None or isinstance(x, unicode_type):
        return x
    if isinstance(x, byte_type):
        return x.decode(charset, errors)
    return unicode_type(x)


def to_native(x, encoding='ascii'):
    if isinstance(x, str):
        return x
    if is_py2:
        return x.encode(encoding)
    return x.decode(encoding)


def json_loads(s):
    return json.loads(s)


def json_dumps(data, ensure_ascii=False):
    return json.dumps(data, ensure_ascii=ensure_ascii, separators=(',', ':'))


def urlsafe_b64decode(s):
    s += b'=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def urlsafe_b64encode(s):
    return base64.urlsafe_b64encode(s).rstrip(b'=')


def base64_to_int(s):
    data = urlsafe_b64decode(to_bytes(s, charset='ascii'))
    buf = struct.unpack('%sB' % len(data), data)
    return int(''.join(["%02x" % byte for byte in buf]), 16)


def int_to_base64(num):
    if num < 0:
        raise ValueError('Must be a positive integer')

    if hasattr(int, 'to_bytes'):
        s = num.to_bytes((num.bit_length() + 7) // 8, 'big', signed=False)
    else:
        buf = []
        while num:
            num, remainder = divmod(num, 256)
            buf.append(remainder)
        buf.reverse()
        s = struct.pack('%sB' % len(buf), *buf)
    return to_unicode(urlsafe_b64encode(s))


def json_b64encode(text):
    if isinstance(text, dict):
        text = json_dumps(text)
    return urlsafe_b64encode(to_bytes(text))
