from django.dispatch import Signal


#: signal when client is authenticated
client_authenticated = Signal(providing_args=['client', 'grant'])

#: signal when token is revoked
token_revoked = Signal(providing_args=['token', 'client'])

#: signal when token is authenticated
token_authenticated = Signal(providing_args=['token'])
