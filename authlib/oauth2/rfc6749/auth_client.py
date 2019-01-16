import base64
from authlib.common.urls import add_params_to_qs
from authlib.common.encoding import to_bytes, to_native


def sign_client_secret_basic(client, method, uri, headers, body):
    text = '{}:{}'.format(client.client_id, client.client_secret)
    auth = to_native(base64.urlsafe_b64encode(to_bytes(text, 'latin1')))
    headers['Authorization'] = 'Basic {}'.format(auth)
    return uri, headers, body


def sign_client_secret_post(client, method, uri, headers, body):
    body = add_params_to_qs(body or '', [
        ('client_id', client.client_id),
        ('client_secret', client.client_secret or '')
    ])
    return uri, headers, body


def sign_none(client, method, uri, headers, body):
    if method == 'GET':
        uri = add_params_to_qs(uri, [('client_id', client.client_id)])
        return uri, headers, body
    body = add_params_to_qs(body, [('client_id', client.client_id)])
    return uri, headers, body


class AuthClient(object):
    """Attaches OAuth Client Authentication to the given Request object.

    :param client_id: Client ID, which you get from client registration.
    :param client_secret: Client Secret, which you get from registration.
    :param auth_method: Client auth method for token endpoint. The supported
        methods for now:

        * client_secret_basic
        * client_secret_post
        * none
    """
    def __init__(self, client_id, client_secret, auth_method=None):
        if auth_method is None:
            auth_method = 'client_secret_basic'

        self.client_id = client_id
        self.client_secret = client_secret
        self.auth_method = auth_method

        self._auth_methods = {
            'client_secret_basic': sign_client_secret_basic,
            'client_secret_post': sign_client_secret_post,
            'none': sign_none,
        }

    def register(self, method, func):
        assert method not in self._auth_methods
        self._auth_methods[method] = func

    def prepare(self, method, uri, headers, body):
        func = self._auth_methods.get(self.auth_method)
        return func(self, method, uri, headers, body)
