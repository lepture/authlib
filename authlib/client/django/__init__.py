# flake8: noqa
from authlib.common.compat import deprecate
from authlib.django.client import OAuth, RemoteApp

deprecate('Use "from authlib.django.client import OAuth, RemoteApp"')
