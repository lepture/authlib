from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat,
    BestAvailableEncryption, NoEncryption,
)
from authlib.common.encoding import to_bytes
from ..rfc7517 import load_pem_key


def import_key(cls, raw, public_key_cls, private_key_cls, ssh_type=None, options=None):
    if isinstance(raw, cls):
        if options is not None:
            raw.update(options)
        return raw

    payload = None
    if isinstance(raw, (public_key_cls, private_key_cls)):
        raw_key = raw
    elif isinstance(raw, dict):
        cls.check_required_fields(raw)
        payload = raw
        if 'd' in payload:
            raw_key = cls.loads_private_key(payload)
        else:
            raw_key = cls.loads_public_key(payload)
    else:
        if options is not None:
            password = options.get('password')
        else:
            password = None
        raw_key = load_pem_key(raw, ssh_type, password=password)

    if isinstance(raw_key, private_key_cls):
        if payload is None:
            payload = cls.dumps_private_key(raw_key)
        key_type = 'private'
    elif isinstance(raw_key, public_key_cls):
        if payload is None:
            payload = cls.dumps_public_key(raw_key)
        key_type = 'public'
    else:
        raise ValueError('Invalid data for importing key')

    obj = cls(payload)
    obj.raw_key = raw_key
    obj.key_type = key_type
    return obj


def export_key(key, encoding=None, is_private=False, password=None):
    if encoding is None or encoding == 'PEM':
        encoding = Encoding.PEM
    elif encoding == 'DER':
        encoding = Encoding.DER
    else:
        raise ValueError('Invalid encoding: {!r}'.format(encoding))

    if is_private:
        if key.key_type == 'private':
            if password is None:
                encryption_algorithm = NoEncryption()
            else:
                encryption_algorithm = BestAvailableEncryption(to_bytes(password))
            return key.raw_key.private_bytes(
                encoding=encoding,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm,
            )
        raise ValueError('This is a public key')

    if key.key_type == 'private':
        raw_key = key.raw_key.public_key()
    else:
        raw_key = key.raw_key

    return raw_key.public_bytes(
        encoding=encoding,
        format=PublicFormat.SubjectPublicKeyInfo,
    )
