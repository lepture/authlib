from flask.signals import Namespace

_signal = Namespace()

client_authenticated = _signal.signal('client_authenticated')
token_authenticated = _signal.signal('token_authenticated')
token_revoked = _signal.signal('token_revoked')
