from requests.compat import str, bytes


def to_bytes(x, charset='UTF-8', errors='strict'):
    if x is None:
        return None
    if isinstance(x, (bytes, bytearray)):
        return bytes(x)
    if isinstance(x, str):
        return x.encode(charset, errors)
    raise TypeError('Expected bytes')


def to_native(x, charset='UTF-8', errors='strict'):
    if x is None or isinstance(x, str):
        return x
    return x.decode(charset, errors)


def to_unicode(x, charset='UTF-8', errors='strict', allow_none_charset=False):
    if x is None:
        return None
    if not isinstance(x, bytes):
        return str(x)
    if charset is None and allow_none_charset:
        return x
    return x.decode(charset, errors)
