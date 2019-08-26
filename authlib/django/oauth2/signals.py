from django.dispatch import Signal


client_authenticated = Signal(providing_args=['client', 'grant'])
token_revoked = Signal(providing_args=['token', 'client'])
token_authenticated = Signal(providing_args=['token'])
