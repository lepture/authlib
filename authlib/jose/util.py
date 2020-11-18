import binascii
from authlib.common.encoding import urlsafe_b64decode, json_loads


def extract_header(header_segment, error_cls):
    header_data = extract_segment(header_segment, error_cls, 'header')

    try:
        header = json_loads(header_data.decode('utf-8'))
    except ValueError as e:
        raise error_cls('Invalid header string: {}'.format(e))

    if not isinstance(header, dict):
        raise error_cls('Header must be a json object')
    return header


def extract_segment(segment, error_cls, name='payload'):
    try:
        return urlsafe_b64decode(segment)
    except (TypeError, binascii.Error):
        msg = 'Invalid {} padding'.format(name)
        raise error_cls(msg)
