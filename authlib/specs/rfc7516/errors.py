from authlib.specs.rfc7515.errors import JWSError
from authlib.specs.rfc7515.errors import (
    DecodeError, MissingAlgorithmError, UnsupportedAlgorithmError,
    BadSignatureError, InvalidHeaderParameterName
)

__all__ = [
    'JWEError', 'DecodeError', 'MissingAlgorithmError',
    'UnsupportedAlgorithmError', 'BadSignatureError',
    'InvalidHeaderParameterName', 'MissingEncryptionAlgorithmError',
    'UnsupportedEncryptionAlgorithmError',
    'UnsupportedCompressionAlgorithmError',
]

JWEError = JWSError


class MissingEncryptionAlgorithmError(JWEError):
    error = 'missing_encryption_algorithm'
    description = 'Missing "enc" in header'


class UnsupportedEncryptionAlgorithmError(JWEError):
    error = 'unsupported_encryption_algorithm'
    description = 'Unsupported "enc" value in header'


class UnsupportedCompressionAlgorithmError(JWEError):
    error = 'unsupported_compression_algorithm'
    description = 'Unsupported "zip" value in header'
