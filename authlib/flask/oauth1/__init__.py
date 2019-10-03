# flake8: noqa

from authlib.integrations.flask_oauth1 import (
    AuthorizationServer,
    ResourceProtector,
    current_credential,
)
from authlib.deprecate import deprecate

deprecate('Deprecate "authlib.flask.oauth1", USE "authlib.integrations.flask_oauth1" instead.', '1.0', 'Jeclj', 'rn')
