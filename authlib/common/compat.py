import warnings


class AuthlibDeprecationWarning(DeprecationWarning):
    pass


warnings.simplefilter('always', AuthlibDeprecationWarning)


def deprecate(message, stacklevel=2):
    warnings.warn(AuthlibDeprecationWarning(message), stacklevel=stacklevel)
