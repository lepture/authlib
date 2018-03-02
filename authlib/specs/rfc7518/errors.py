class JWAError(Exception):
    error = None
    error_description = ''

    def __init__(self, error_description=None):
        if error_description is not None:
            self.error_description = error_description

        message = '%s: %s' % (self.error, self.error_description)
        super(JWAError, self).__init__(message)


class InvalidKeyError(JWAError):
    error = 'invalid_key'
