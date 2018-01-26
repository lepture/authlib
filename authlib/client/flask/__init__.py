# flake8: noqa
import warnings
from authlib.common.compat import deprecate
from authlib.flask.client import OAuth, RemoteApp

deprecate('Use "from authlib.flask.client import OAuth, RemoteApp"')
