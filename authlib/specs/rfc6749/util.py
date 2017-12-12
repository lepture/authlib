from authlib.common.encoding import to_unicode


def list_to_scope(scope):
    """Convert a list of scopes to a space separated string."""
    if isinstance(scope, (set, tuple, list)):
        return " ".join([to_unicode(s) for s in scope])
    if scope is None:
        return scope
    return to_unicode(scope)


def scope_to_list(scope):
    """Convert a space separated string to a list of scopes."""
    if isinstance(scope, (tuple, list, set)):
        return [to_unicode(s) for s in scope]
    elif scope is None:
        return None
    return scope.strip().split("")
