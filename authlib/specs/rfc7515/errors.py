
class JWSError(Exception):
    error = None
    error_description = ''

    def __init__(self, error_description=None):
        if error_description is not None:
            self.error_description = error_description

        message = '%s: %s' % (self.error, self.error_description)
        super(JWSError, self).__init__(message)


class DecodeError(JWSError):
    error = 'decode_error'


class MissingAlgorithmError(JWSError):
    error = 'missing_algorithm'


class UnsupportedAlgorithmError(JWSError):
    error = 'unsupported_algorithm'


class BadSignatureError(JWSError):
    error = 'bad_signature'
