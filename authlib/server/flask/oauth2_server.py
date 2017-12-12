from werkzeug.utils import import_string
from flask import request, Response, json
from authlib.specs.rfc6749 import (
    OAuth2Error,
    AuthorizationServer as _AuthorizationServer
)
from authlib.specs.rfc6750 import BearerToken
from authlib.specs.rfc7009 import RevocationEndpoint
from authlib.common.security import generate_token

GRANT_TYPES_EXPIRES = {
    'authorization_code': 864000,
    'implicit': 3600,
    'password': 864000,
    'client_credential': 864000
}


class AuthorizationServer(_AuthorizationServer):
    def __init__(self, app=None, client_model=None):
        super(AuthorizationServer, self).__init__(client_model, None)
        self.revoke_query_token = None
        self.app = None
        if app is not None:
            self.init_app(app)

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
        grant = self.get_authorization_endpoint_grant(request.full_path)
        grant.validate_authorization_request()
        return grant

    def create_authorization_response(self, user):
        grant = self.get_authorization_endpoint_grant(request.full_path)
        grant.validate_authorization_request()
        status, body, headers = grant.create_authorization_response(user)
        return Response('', status=status, headers=headers)

    def create_token_response(self):
        grant = self.get_access_token_endpoint_grant(
            request.method,
            request.full_path,
            request.form.to_dict(flat=True),
            request.headers
        )
        try:
            grant.validate_access_token_request()
            status, body, headers = grant.create_access_token_response()
        except OAuth2Error as error:
            status = error.status_code
            body = dict(error.get_body())
            headers = error.get_headers()
        return Response(json.dumps(body), status=status, headers=headers)

    def create_revocation_response(self):
        if request.method == 'GET':
            params = request.args.to_dict(flat=True)
        else:
            params = request.form.to_dict(flat=True)

        endpoint = RevocationEndpoint(
            request.full_path, params, request.headers,
            self.client_model, self.revoke_query_token
        )
        status, body, headers = endpoint.create_revocation_response()
        return Response(json.dumps(body), status=status, headers=headers)
