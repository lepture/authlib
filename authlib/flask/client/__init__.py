# flake8: noqa

from authlib.deprecate import deprecate
from authlib.integrations.flask_client import OAuth, RemoteApp

deprecate('Deprecate "authlib.flask.client", USE "authlib.integrations.flask_client" instead.', '1.0', 'Jeclj', 'rn')
