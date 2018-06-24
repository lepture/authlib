from authlib.common.errors import AuthlibBaseError


class JWEError(AuthlibBaseError):
    pass


class DecodeError(JWEError):
    error = 'decode_error'


class MissingAlgorithmError(JWEError):
    error = 'missing_algorithm'
    description = 'Missing "alg" in header'


class UnsupportedAlgorithmError(JWEError):
    error = 'unsupported_algorithm'
    description = 'Unsupported "alg" value in header'


class MissingEncryptionAlgorithmError(JWEError):
    error = 'missing_encryption_algorithm'
    description = 'Missing "enc" in header'


class UnsupportedEncryptionAlgorithmError(JWEError):
    error = 'unsupported_encryption_algorithm'
    description = 'Unsupported "enc" value in header'


class UnsupportedCompressionAlgorithmError(JWEError):
    error = 'unsupported_compression_algorithm'
    description = 'Unsupported "zip" value in header'


class BadSignatureError(JWEError):
    error = 'bad_signature'


class InvalidHeaderParameterName(JWEError):
    error = 'invalid_header_parameter_name'

    def __init__(self, name):
        description = 'Invalid Header Parameter Names: {}'.format(name)
        super(InvalidHeaderParameterName, self).__init__(
            description=description)
