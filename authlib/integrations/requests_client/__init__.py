from .oauth1_session import OAuth1Session, OAuth1Auth
from .oauth2_session import OAuth2Session, OAuth2Auth
from .assertion_session import AssertionSession
from ..client_errors import OAuthError
from ..oauth_client import OAuthClient as _OAuthClient


class OAuthClient(_OAuthClient):
    oauth1_client_cls = OAuth1Session
    oauth2_client_cls = OAuth2Session


__all__ = [
    'OAuth1Session', 'OAuth1Auth',
    'OAuth2Session', 'OAuth2Auth',
    'OAuthError',
    'AssertionSession',
    'OAuthClient',
]
