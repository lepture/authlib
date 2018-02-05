import warnings


class AuthlibDeprecationWarning(DeprecationWarning):
    pass


warnings.simplefilter('always', AuthlibDeprecationWarning)


def deprecate(message, version=None, stacklevel=2):
    if version:
        message += '\n\nIt will be compatible until version {}.'.format(version)
    warnings.warn(AuthlibDeprecationWarning(message), stacklevel=stacklevel)
