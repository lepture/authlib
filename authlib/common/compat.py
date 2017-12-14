import warnings


class AuthlibDeprecationWarning(DeprecationWarning):
    pass


warnings.simplefilter('always', AuthlibDeprecationWarning)
