from ..rfc7515 import JWSError

__all__ = [
    'JWTError', 'InvalidClaimError',
    'MissingClaimError', 'InsecureClaimError',
    'ExpiredTokenError', 'InvalidTokenError',
]


JWTError = JWSError


class InvalidClaimError(JWTError):
    error = 'invalid_claim'

    def __init__(self, claim):
        description = 'Invalid claim "{}"'.format(claim)
        super(InvalidClaimError, self).__init__(description)


class MissingClaimError(JWTError):
    error = 'missing_claim'

    def __init__(self, claim):
        description = 'Missing "{}" claim'.format(claim)
        super(MissingClaimError, self).__init__(description)


class InsecureClaimError(JWTError):
    error = 'insecure_claim'

    def __init__(self, claim):
        description = 'Insecure claim "{}"'.format(claim)
        super(InsecureClaimError, self).__init__(description)


class ExpiredTokenError(JWTError):
    error = 'expired_token'
    error_description = 'The token is expired'


class InvalidTokenError(JWTError):
    error = 'invalid_token'
    error_description = 'The token is not valid yet'
