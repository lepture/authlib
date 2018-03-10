__all__ = [
    'JWTError', 'InvalidClaimError', 'MissingClaimError',
    'ExpiredTokenError', 'InvalidTokenError',
]


class JWTError(Exception):
    error = None
    error_description = ''

    def __init__(self, error_description=None):
        if error_description is not None:
            self.error_description = error_description
        message = '%s: %s' % (self.error, self.error_description)
        super(JWTError, self).__init__(message)


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


class ExpiredTokenError(JWTError):
    error = 'expired_token'
    error_description = 'The token is expired'


class InvalidTokenError(JWTError):
    error = 'invalid_token'
    error_description = 'The token is not valid yet'
