# flake8: noqa
import warnings
from authlib.common.compat import AuthlibDeprecationWarning
from authlib.django.client import OAuth, RemoteApp

warnings.warn(AuthlibDeprecationWarning(
    'Please use "from authlib.django.client import OAuth, RemoteApp"'
), stacklevel=2)
