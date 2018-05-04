from authlib.errors import AuthlibBaseError

__all__ = [
    'JWSError', 'DecodeError', 'MissingAlgorithmError',
    'UnsupportedAlgorithmError', 'BadSignatureError',
    'InvalidHeaderParameterName',
]


JWSError = AuthlibBaseError


class DecodeError(JWSError):
    error = 'decode_error'


class MissingAlgorithmError(JWSError):
    error = 'missing_algorithm'


class UnsupportedAlgorithmError(JWSError):
    error = 'unsupported_algorithm'


class BadSignatureError(JWSError):
    error = 'bad_signature'


class InvalidHeaderParameterName(JWSError):
    error = 'invalid_header_parameter_name'

    def __init__(self, name):
        description = 'Invalid Header Parameter Names: {}'.format(name)
        super(InvalidHeaderParameterName, self).__init__(
            description=description)
