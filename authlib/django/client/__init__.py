# flake8: noqa

from authlib.deprecate import deprecate
from authlib.integrations.django_client import OAuth, RemoteApp

deprecate('Deprecate "authlib.django.client", USE "authlib.integrations.django_client" instead.', '1.0', 'Jeclj', 'rn')
