import warnings


class AuthlibDeprecationWarning(DeprecationWarning):
    pass


warnings.simplefilter('always', AuthlibDeprecationWarning)


def deprecate(message, version=None, link_uid=None, link_file=None):
    if version:
        message += '\nIt will be compatible before version {}.'.format(version)
    if link_uid and link_file:
        message += '\nRead more <https://git.io/{}#file-{}-md>'.format(link_uid, link_file)
    warnings.warn(AuthlibDeprecationWarning(message), stacklevel=2)
