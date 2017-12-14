from authlib.common.urls import urlparse, url_decode
from authlib.common.urls import add_params_to_uri
from .errors import InvalidGrantError, OAuth2Error


class AuthorizationServer(object):
    def __init__(self, client_model, token_generator):
        self.client_model = client_model
        self.token_generator = token_generator
        self._authorization_endpoints = set()
        self._access_token_endpoints = set()

    def register_grant_endpoint(self, grant_cls):
        if grant_cls.AUTHORIZATION_ENDPOINT:
            self._authorization_endpoints.add(grant_cls)
        if grant_cls.ACCESS_TOKEN_ENDPOINT:
            self._access_token_endpoints.add(grant_cls)

    def get_authorization_grant(self, uri):
        params = dict(url_decode(urlparse.urlparse(uri).query))
        for grant_cls in self._authorization_endpoints:
            if grant_cls.check_authorization_endpoint(params):
                return grant_cls(
                    uri, params, {},
                    self.client_model,
                    self.token_generator
                )
        raise InvalidGrantError()

    def get_token_grant(self, method, uri, body, headers):
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

    def create_valid_authorization_response(self, uri, user):
        try:
            grant = self.get_authorization_grant(uri)
        except InvalidGrantError as error:
            body = dict(error.get_body())
            return error.status_code, body, error.get_headers()
        try:
            grant.validate_authorization_request()
            return grant.create_authorization_response(user)
        except OAuth2Error as error:
            params = error.get_body()
            loc = add_params_to_uri(grant.redirect_uri, params)
            headers = [('Location', loc)]
            return 302, '', headers

    def create_valid_token_response(self, method, uri, body, headers):
        try:
            grant = self.get_token_grant(method, uri, body, headers)
        except InvalidGrantError as error:
            body = dict(error.get_body())
            return error.status_code, body, error.get_headers()
        try:
            grant.validate_access_token_request()
            return grant.create_access_token_response()
        except OAuth2Error as error:
            status = error.status_code
            body = dict(error.get_body())
            headers = error.get_headers()
            return status, body, headers
