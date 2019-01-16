from authlib.common.urls import add_params_to_qs
from .client import ASSERTION_TYPE
from .client import client_secret_jwt_sign, private_key_jwt_sign


def register_session_client_auth_method(session, token_url=None, **kwargs):
    """Register "client_secret_jwt" or "private_key_jwt" token endpoint auth
    method to OAuth2Session.

    :param session: OAuth2Session instance.
    :param token_url: Optional token endpoint url.
    """
    if session.token_endpoint_auth_method == 'client_secret_jwt':
        func = client_secret_jwt_sign
    elif session.token_endpoint_auth_method == 'private_key_jwt':
        func = private_key_jwt_sign
    else:
        raise ValueError('Invalid token_endpoint_auth_method')

    def _auth(client, method, uri, headers, body):
        if token_url:
            _url = token_url
        else:
            _url = uri

        client_assertion = func(
            client.client_secret,
            client_id=client.client_id,
            token_url=_url,
            **kwargs
        )
        body = add_params_to_qs(body or '', [
            ('client_assertion_type', ASSERTION_TYPE),
            ('client_assertion', client_assertion)
        ])
        return uri, headers, body

    session.register_client_auth_method(_auth)
