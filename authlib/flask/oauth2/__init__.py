# flake8: noqa

from authlib.deprecate import deprecate
from authlib.integrations.flask_oauth2 import (
    AuthorizationServer,
    ResourceProtector,
    current_token,
    client_authenticated,
    token_authenticated,
    token_revoked,
)
from .cache import register_cache_authorization_code

deprecate('Deprecate "authlib.flask.oauth2", USE "authlib.integrations.flask_oauth2" instead.', '1.0', 'Jeclj', 'rn')
