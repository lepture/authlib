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
