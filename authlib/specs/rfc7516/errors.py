from authlib.jose.errors import (
    JoseError, DecodeError, MissingAlgorithmError,
    UnsupportedAlgorithmError, BadSignatureError,
    InvalidHeaderParameterName, MissingEncryptionAlgorithmError,
    UnsupportedEncryptionAlgorithmError,
    UnsupportedCompressionAlgorithmError,
)

__all__ = [
    'JWEError', 'DecodeError', 'MissingAlgorithmError',
    'UnsupportedAlgorithmError', 'BadSignatureError',
    'InvalidHeaderParameterName', 'MissingEncryptionAlgorithmError',
    'UnsupportedEncryptionAlgorithmError',
    'UnsupportedCompressionAlgorithmError',
]

JWEError = JoseError
