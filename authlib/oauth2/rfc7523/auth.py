from authlib.common.urls import add_params_to_qs
from authlib.deprecate import deprecate
from .assertion import client_secret_jwt_sign, private_key_jwt_sign
from .client import ASSERTION_TYPE


class ClientSecretJWT(object):
    """Authentication method for OAuth 2.0 Client. This authentication
    method is called ``client_secret_jwt``, which is using ``client_id``
    and ``client_secret`` constructed with JWT to identify a client.

    Here is an example of use ``client_secret_jwt`` with Requests Session::

        from authlib.integrations.requests_client import OAuth2Session

        token_endpoint = 'https://example.com/oauth/token'
        session = OAuth2Session(
            'your-client-id', 'your-client-secret',
            token_endpoint_auth_method='client_secret_jwt'
        )
        session.register_client_auth_method(ClientSecretJWT(token_endpoint))
        session.fetch_token(token_endpoint)

    :param token_endpoint: A string URL of the token endpoint
    :param claims: Extra JWT claims
    """
    name = 'client_secret_jwt'

    def __init__(self, token_endpoint=None, claims=None):
        self.token_endpoint = token_endpoint
        self.claims = claims

    def sign(self, auth, token_endpoint):
        return client_secret_jwt_sign(
            auth.client_secret,
            client_id=auth.client_id,
            token_endpoint=token_endpoint,
            claims=self.claims,
        )

    def __call__(self, auth, method, uri, headers, body):
        token_endpoint = self.token_endpoint
        if not token_endpoint:
            token_endpoint = uri

        client_assertion = self.sign(auth, token_endpoint)
        body = add_params_to_qs(body or '', [
            ('client_assertion_type', ASSERTION_TYPE),
            ('client_assertion', client_assertion)
        ])
        return uri, headers, body


class PrivateKeyJWT(ClientSecretJWT):
    """Authentication method for OAuth 2.0 Client. This authentication
    method is called ``private_key_jwt``, which is using ``client_id``
    and ``private_key`` constructed with JWT to identify a client.

    Here is an example of use ``private_key_jwt`` with Requests Session::

        from authlib.integrations.requests_client import OAuth2Session

        token_endpoint = 'https://example.com/oauth/token'
        session = OAuth2Session(
            'your-client-id', 'your-client-private-key',
            token_endpoint_auth_method='private_key_jwt'
        )
        session.register_client_auth_method(PrivateKeyJWT(token_endpoint))
        session.fetch_token(token_endpoint)

    :param token_endpoint: A string URL of the token endpoint
    :param claims: Extra JWT claims
    """
    name = 'private_key_jwt'

    def sign(self, auth, token_endpoint):
        return private_key_jwt_sign(
            auth.client_secret,
            client_id=auth.client_id,
            token_endpoint=token_endpoint,
            claims=self.claims,
        )


def register_session_client_auth_method(session, token_url=None, **kwargs):  # pragma: no cover
    """Register "client_secret_jwt" or "private_key_jwt" token endpoint auth
    method to OAuth2Session.

    :param session: OAuth2Session instance.
    :param token_url: Optional token endpoint url.
    """
    deprecate('Use `ClientSecretJWT` and `PrivateKeyJWT` instead', '1.0', 'Jeclj', 'ca')
    if session.token_endpoint_auth_method == 'client_secret_jwt':
        cls = ClientSecretJWT
    elif session.token_endpoint_auth_method == 'private_key_jwt':
        cls = PrivateKeyJWT
    else:
        raise ValueError('Invalid token_endpoint_auth_method')

    session.register_client_auth_method(cls(token_url))
