from authlib.jose.errors import (
    JoseError,
    DecodeError, InvalidClaimError,
    MissingClaimError, InsecureClaimError,
    ExpiredTokenError, InvalidTokenError,
)

__all__ = [
    'JWTError', 'DecodeError', 'InvalidClaimError',
    'MissingClaimError', 'InsecureClaimError',
    'ExpiredTokenError', 'InvalidTokenError',
]

JWTError = JoseError
