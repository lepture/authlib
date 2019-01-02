from authlib.jose.errors import (
    JoseError, DecodeError, MissingAlgorithmError,
    UnsupportedAlgorithmError, BadSignatureError,
    InvalidHeaderParameterName,
)

__all__ = [
    'JWSError', 'DecodeError', 'MissingAlgorithmError',
    'UnsupportedAlgorithmError', 'BadSignatureError',
    'InvalidHeaderParameterName',
]


JWSError = JoseError
