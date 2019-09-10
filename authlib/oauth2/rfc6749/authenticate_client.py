"""
    authlib.oauth2.rfc6749.authenticate_client
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Registry of client authentication methods, with 3 built-in methods:

    1. client_secret_basic
    2. client_secret_post
    3. none

    The "client_secret_basic" method is used a lot in examples of `RFC6749`_,
    but the concept of naming are introduced in `RFC7591`_.

    .. _`RFC6749`: https://tools.ietf.org/html/rfc6749
    .. _`RFC7591`: https://tools.ietf.org/html/rfc7591
"""

import logging
from .errors import InvalidClientError
from .util import extract_basic_authorization

log = logging.getLogger(__name__)

__all__ = ['ClientAuthentication']


class ClientAuthentication(object):
    def __init__(self, query_client):
        self.query_client = query_client
        self._methods = {
            'none': authenticate_none,
            'client_secret_basic': authenticate_client_secret_basic,
            'client_secret_post': authenticate_client_secret_post,
        }

    def register(self, method, func):
        self._methods[method] = func

    def authenticate(self, request, methods):
        for method in methods:
            func = self._methods[method]
            client = func(self.query_client, request)
            if client:
                request.auth_method = method
                return client

        if 'client_secret_basic' in methods:
            raise InvalidClientError(state=request.state, status_code=401)
        raise InvalidClientError(state=request.state)

    def __call__(self, request, methods):
        return self.authenticate(request, methods)


def authenticate_client_secret_basic(query_client, request):
    """Authenticate client by ``client_secret_basic`` method. The client
    uses HTTP Basic for authentication.
    """
    client_id, client_secret = extract_basic_authorization(request.headers)
    if client_id and client_secret:
        client = _validate_client(query_client, client_id, request.state, 401)
        if client.check_token_endpoint_auth_method('client_secret_basic') \
                and client.check_client_secret(client_secret):
            log.debug(
                'Authenticate %s via "client_secret_basic" '
                'success', client_id
            )
            return client
    log.debug(
        'Authenticate %s via "client_secret_basic" '
        'failed', client_id
    )


def authenticate_client_secret_post(query_client, request):
    """Authenticate client by ``client_secret_post`` method. The client
    uses POST parameters for authentication.
    """
    data = request.form
    client_id = data.get('client_id')
    client_secret = data.get('client_secret')
    if client_id and client_secret:
        client = _validate_client(query_client, client_id, request.state)
        if client.check_token_endpoint_auth_method('client_secret_post') \
                and client.check_client_secret(client_secret):
            log.debug(
                'Authenticate %s via "client_secret_post" '
                'success', client_id
            )
            return client
    log.debug(
        'Authenticate %s via "client_secret_post" '
        'failed', client_id
    )


def authenticate_none(query_client, request):
    """Authenticate public client by ``none`` method. The client
    does not have a client secret.
    """
    client_id = request.client_id
    if client_id and 'client_secret' not in request.data:
        client = _validate_client(query_client, client_id, request.state)
        if client.check_token_endpoint_auth_method('none'):
            log.debug(
                'Authenticate %s via "none" '
                'success', client_id
            )
            return client
    log.debug(
        'Authenticate {} via "none" '
        'failed'.format(client_id)
    )


def _validate_client(query_client, client_id, state=None, status_code=400):
    if client_id is None:
        raise InvalidClientError(state=state, status_code=status_code)

    client = query_client(client_id)
    if not client:
        raise InvalidClientError(state=state, status_code=status_code)

    return client
