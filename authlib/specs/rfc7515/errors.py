from authlib.common.errors import AuthlibBaseError

__all__ = [
    'JWSError', 'DecodeError', 'MissingAlgorithmError',
    'UnsupportedAlgorithmError', 'BadSignatureError',
    'InvalidHeaderParameterName',
]


class JWSError(AuthlibBaseError):
    pass


class DecodeError(JWSError):
    error = 'decode_error'


class MissingAlgorithmError(JWSError):
    error = 'missing_algorithm'


class UnsupportedAlgorithmError(JWSError):
    error = 'unsupported_algorithm'


class BadSignatureError(JWSError):
    error = 'bad_signature'

    def __init__(self, result):
        super(BadSignatureError, self).__init__()
        self.result = result


class InvalidHeaderParameterName(JWSError):
    error = 'invalid_header_parameter_name'

    def __init__(self, name):
        description = 'Invalid Header Parameter Names: {}'.format(name)
        super(InvalidHeaderParameterName, self).__init__(
            description=description)
