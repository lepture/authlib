# flake8: noqa

from authlib.deprecate import deprecate
from authlib.integrations.requests_client import (
    OAuth1Session, OAuth1Auth,
    OAuth2Session, OAuth2Auth,
    AssertionSession,
)
from .oauth_client import OAuthClient, OAUTH_CLIENT_PARAMS
from .errors import *

deprecate('Deprecate "authlib.client", USE "authlib.integrations.requests_client" instead.', '1.0', 'Jeclj', 'rn')
