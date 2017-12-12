from authlib.common.urls import urlparse, url_decode
from .errors import InvalidGrantError


class AuthorizationServer(object):
    def __init__(self, client_model, token_generator):
        self.client_model = client_model
        self.token_generator = token_generator
        self._authorization_endpoints = set()
        self._access_token_endpoints = set()

    def register_endpoint_grant(self, grant_cls):
        if grant_cls.AUTHORIZATION_ENDPOINT:
            self._authorization_endpoints.add(grant_cls)
        if grant_cls.ACCESS_TOKEN_ENDPOINT:
            self._access_token_endpoints.add(grant_cls)

    def get_authorization_endpoint_grant(self, uri):
        params = dict(url_decode(urlparse.urlparse(uri).query))
        for grant_cls in self._authorization_endpoints:
            if grant_cls.check_authorization_endpoint(params):
                return grant_cls(
                    uri, params, {},
                    self.client_model,
                    self.token_generator
                )
        raise InvalidGrantError()

    def get_access_token_endpoint_grant(self, method, uri, body, headers):
        if method == 'GET':
            params = dict(url_decode(urlparse.urlparse(uri).query))
        else:
            if isinstance(body, dict):
                params = body
            else:
                params = dict(url_decode(body))

        for grant_cls in self._access_token_endpoints:
            if grant_cls.check_token_endpoint(params):
                if method in grant_cls.ACCESS_TOKEN_METHODS:
                    return grant_cls(
                        uri, params, headers,
                        self.client_model,
                        self.token_generator
                    )
        raise InvalidGrantError()
