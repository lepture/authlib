import time
import functools
from werkzeug.utils import import_string
from flask import request, Response, json
from authlib.specs.rfc6749 import (
    OAuth2Error,
    AuthorizationServer as _AuthorizationServer,
    ResourceServer as _ResourceServer,
)
from authlib.specs.rfc6750 import BearerToken
from authlib.common.security import generate_token

GRANT_TYPES_EXPIRES = {
    'authorization_code': 864000,
    'implicit': 3600,
    'password': 864000,
    'client_credential': 864000
}


class AuthorizationServer(_AuthorizationServer):
    def __init__(self, client_model, app=None):
        super(AuthorizationServer, self).__init__(client_model, None)
        self.revoke_token_endpoint = None
        self.app = None
        if app is not None:
            self.init_app(app)

    def register_revoke_token_endpoint(self, cls):
        self.revoke_token_endpoint = cls

    def init_app(self, app):
        for k in GRANT_TYPES_EXPIRES:
            conf_key = 'OAUTH2_EXPIRES_{}'.format(k.upper())
            app.config.setdefault(conf_key, GRANT_TYPES_EXPIRES[k])

        self.app = app
        self.token_generator = self.create_bearer_token_generator(app)

    def create_expires_generator(self, app):

        def expires_in(client, grant_type):
            conf_key = 'OAUTH2_EXPIRES_{}'.format(grant_type.upper())
            return app.config.get(conf_key, BearerToken.DEFAULT_EXPIRES_IN)

        return expires_in

    def create_bearer_token_generator(self, app):
        access_token_generator = app.config.get(
            'OAUTH2_ACCESS_TOKEN_GENERATOR',
            True
        )

        if isinstance(access_token_generator, str):
            access_token_generator = import_string(access_token_generator)
        else:
            access_token_generator = lambda: generate_token(42)

        refresh_token_generator = app.config.get(
            'OAUTH2_REFRESH_TOKEN_GENERATOR',
            False
        )
        if isinstance(refresh_token_generator, str):
            refresh_token_generator = import_string(refresh_token_generator)
        elif refresh_token_generator is True:
            refresh_token_generator = lambda: generate_token(48)
        else:
            refresh_token_generator = None

        expires_generator = self.create_expires_generator(app)
        return BearerToken(
            access_token_generator,
            refresh_token_generator,
            expires_generator
        )

    def validate_authorization_request(self):
        grant = self.get_authorization_grant(request.full_path)
        grant.validate_authorization_request()
        return grant

    def create_authorization_response(self, user):
        status, body, headers = self.create_valid_authorization_response(
            request.full_path, user=user
        )
        if isinstance(body, dict):
            body = json.dumps(body)
        return Response(body, status=status, headers=headers)

    def create_token_response(self):
        status, body, headers = self.create_valid_token_response(
            request.method,
            request.full_path,
            request.form.to_dict(flat=True),
            request.headers
        )
        return Response(json.dumps(body), status=status, headers=headers)

    def create_revocation_response(self):
        if request.method == 'GET':
            params = request.args.to_dict(flat=True)
        else:
            params = request.form.to_dict(flat=True)

        endpoint = self.revoke_token_endpoint(
            request.full_path, params, request.headers, self.client_model
        )
        status, body, headers = endpoint.create_revocation_response()
        return Response(json.dumps(body), status=status, headers=headers)


class ResourceServer(_ResourceServer):
    def __init__(self, query_token, query_token_user):
        self.query_token = query_token
        self.query_token_user = query_token_user

    def authenticate_token(self, token_string, token_type):
        if token_type.lower() == 'bearer':
            return self.query_token(token_string)

    def get_token_user(self, token):
        return self.query_token_user(token)

    def get_token_scope(self, token):
        return token.scope

    def is_token_expired(self, token):
        return token.expires_at < time.time()

    def __call__(self, scope):
        def wrapper(f):
            @functools.wraps(f)
            def decorated(*args, **kwargs):
                try:
                    token = self.validate_request(request.headers, scope)
                    request.token = token
                except OAuth2Error as error:
                    status = error.status_code
                    body = dict(error.get_body())
                    headers = error.get_headers()
                    return Response(json.dumps(body), status=status, headers=headers)
                return f(*args, **kwargs)
            return decorated
        return wrapper
