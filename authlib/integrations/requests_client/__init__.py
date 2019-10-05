from .oauth1_session import OAuth1Session, OAuth1Auth
from .oauth2_session import OAuth2Session, OAuth2Auth
from .assertion_session import AssertionSession
from ..client_errors import OAuthError
from ..oauth_client import OAuthClient as _OAuthClient
from authlib.oauth1 import (
    SIGNATURE_HMAC_SHA1,
    SIGNATURE_RSA_SHA1,
    SIGNATURE_PLAINTEXT,
    SIGNATURE_TYPE_HEADER,
    SIGNATURE_TYPE_QUERY,
    SIGNATURE_TYPE_BODY,
)


class OAuthClient(_OAuthClient):
    oauth1_client_cls = OAuth1Session
    oauth2_client_cls = OAuth2Session


__all__ = [
    'OAuthError',
    'OAuth1Session', 'OAuth1Auth',
    'SIGNATURE_HMAC_SHA1', 'SIGNATURE_RSA_SHA1', 'SIGNATURE_PLAINTEXT',
    'SIGNATURE_TYPE_HEADER', 'SIGNATURE_TYPE_QUERY', 'SIGNATURE_TYPE_BODY',
    'OAuth2Session', 'OAuth2Auth',
    'AssertionSession',
    'OAuthClient',
]
