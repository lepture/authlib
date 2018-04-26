"""
    authlib.rfc6749.authenticate_client
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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

__all__ = ['authenticate_client']


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
                'Authenticate {} via "client_secret_basic" '
                'success'.format(client_id)
            )
            return client
    log.debug(
        'Authenticate {} via "client_secret_basic" '
        'failed'.format(client_id)
    )


def authenticate_client_secret_post(query_client, request):
    """Authenticate client by ``client_secret_post`` method. The client
    uses POST parameters for authentication.
    """
    data = dict(request.body_params)
    client_id = data.get('client_id')
    client_secret = data.get('client_secret')
    if client_id and client_secret:
        client = _validate_client(query_client, client_id, request.state)
        if client.check_token_endpoint_auth_method('client_secret_post') \
                and client.check_client_secret(client_secret):
            log.debug(
                'Authenticate {} via "client_secret_post" '
                'success'.format(client_id)
            )
            return client
    log.debug(
        'Authenticate {} via "client_secret_post" '
        'failed'.format(client_id)
    )


def authenticate_none(query_client, request):
    """Authenticate public client by ``none`` method. The client
    does not have a client secret.
    """
    client_id = request.client_id
    if client_id and 'client_secret' not in request.data:
        client = _validate_client(query_client, client_id, request.state)
        if client.check_token_endpoint_auth_method('none') \
                and not client.has_client_secret():
            log.debug(
                'Authenticate {} via "none" '
                'success'.format(client_id)
            )
            return client
    log.debug(
        'Authenticate {} via "none" '
        'failed'.format(client_id)
    )


AUTHENTICATE_METHODS = {
    'none': authenticate_none,
    'client_secret_basic': authenticate_client_secret_basic,
    'client_secret_post': authenticate_client_secret_post,
}


def authenticate_client(query_client, request, methods, available=None):
    """Authenticate client with the given methods."""
    if available is None:
        available = AUTHENTICATE_METHODS

    for method in methods:
        func = available[method]
        client = func(query_client, request)
        if client:
            return client

    if 'client_secret_basic' in methods:
        raise InvalidClientError(state=request.state, status_code=401)
    raise InvalidClientError(state=request.state)


def _validate_client(query_client, client_id, state=None, status_code=400):
    if client_id is None:
        raise InvalidClientError(state=state, status_code=status_code)

    client = query_client(client_id)
    if not client:
        raise InvalidClientError(state=state, status_code=status_code)

    return client
