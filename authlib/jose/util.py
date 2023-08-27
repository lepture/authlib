import binascii
from authlib.common.encoding import urlsafe_b64decode, json_loads, to_unicode
from authlib.jose.errors import DecodeError


def extract_header(header_segment, error_cls):
    header_data = extract_segment(header_segment, error_cls, 'header')

    try:
        header = json_loads(header_data.decode('utf-8'))
    except ValueError as e:
        raise error_cls(f'Invalid header string: {e}')

    if not isinstance(header, dict):
        raise error_cls('Header must be a json object')
    return header


def extract_segment(segment, error_cls, name='payload'):
    try:
        return urlsafe_b64decode(segment)
    except (TypeError, binascii.Error):
        msg = f'Invalid {name} padding'
        raise error_cls(msg)


def ensure_dict(s, structure_name):
    if not isinstance(s, dict):
        try:
            s = json_loads(to_unicode(s))
        except (ValueError, TypeError):
            raise DecodeError(f'Invalid {structure_name}')

    if not isinstance(s, dict):
        raise DecodeError(f'Invalid {structure_name}')

    return s
