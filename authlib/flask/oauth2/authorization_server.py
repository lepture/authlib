from werkzeug.utils import import_string
from flask import Response, json
from flask import request as flask_req
from authlib.specs.rfc6749 import (
    OAuth2Request,
    register_error_uri,
    AuthorizationServer as _AuthorizationServer,
)
from authlib.specs.rfc6750 import BearerToken
from authlib.common.security import generate_token
from authlib.common.encoding import to_unicode
from authlib.deprecate import deprecate
from .signals import client_authenticated, token_revoked

GRANT_TYPES_EXPIRES = {
    'authorization_code': 864000,
    'implicit': 3600,
    'password': 864000,
    'client_credentials': 864000
}


class AuthorizationServer(_AuthorizationServer):
    """Flask implementation of :class:`authlib.rfc6749.AuthorizationServer`.
    Initialize it with ``query_client``, ``save_token`` methods and Flask
    app instance::

        def query_client(client_id):
            return Client.query.filter_by(client_id=client_id).first()

        def save_token(token, request):
            if request.user:
                user_id = request.user.get_user_id()
            else:
                user_id = None
            client = request.client
            tok = Token(
                client_id=client.client_id,
                user_id=user.get_user_id(),
                **token
            )
            db.session.add(tok)
            db.session.commit()

        server = AuthorizationServer(app, query_client, save_token)
        # or initialize lazily
        server = AuthorizationServer()
        server.init_app(app, query_client, save_token)
    """
    def __init__(self, app=None, query_client=None, save_token=None, **config):
        super(AuthorizationServer, self).__init__(
            query_client, None, save_token, **config)

        # register hooks
        def after_authenticate_client(client, grant):
            client_authenticated.send(self, client=client, grant=grant)

        def after_revoke_token(token, client):
            token_revoked.send(self, token=token, client=client)

        self.register_hook(
            'after_authenticate_client',
            after_authenticate_client
        )
        self.register_hook('after_revoke_token', after_revoke_token)

        self.app = app
        if app is not None:
            self.init_app(app)

    def register_revoke_token_endpoint(self, cls):  # pragma: no cover
        deprecate('Use "register_endpoint" instead.', '0.8', 'vAAUK', 're')
        self.register_endpoint(cls)

    def init_app(self, app, query_client=None, save_token=None):
        """Initialize later with Flask app instance."""
        if query_client is not None:
            self.query_client = query_client
        if save_token is not None:
            self.save_token = save_token

        # register error uri
        error_uris = app.config.get('OAUTH2_ERROR_URIS')
        if error_uris:
            for k, v in error_uris:
                register_error_uri(k, v)

        self.app = app
        self.generate_token = self.create_bearer_token_generator(app)
        if app.config.get('OAUTH2_JWT_ENABLED'):
            self.init_jwt_config(app)

    def init_jwt_config(self, app):
        """Initialize JWT related configuration."""
        jwt_iss = app.config.get('OAUTH2_JWT_ISS')
        if not jwt_iss:
            raise RuntimeError('Missing "OAUTH2_JWT_ISS" configuration.')
        jwt_key_path = app.config.get('OAUTH2_JWT_KEY_PATH')
        if jwt_key_path:
            with open(jwt_key_path, 'r') as f:
                if jwt_key_path.endswith('.json'):
                    jwt_key = json.load(f)
                else:
                    jwt_key = to_unicode(f.read())
        else:
            jwt_key = app.config.get('OAUTH2_JWT_KEY')

        if not jwt_key:
            raise RuntimeError('Missing "OAUTH2_JWT_KEY" configuration.')

        jwt_alg = app.config.get('OAUTH2_JWT_ALG')
        if not jwt_alg:
            raise RuntimeError('Missing "OAUTH2_JWT_ALG" configuration.')

        jwt_exp = app.config.get('OAUTH2_JWT_EXP', 3600)
        self.config.setdefault('jwt_iss', jwt_iss)
        self.config.setdefault('jwt_key', jwt_key)
        self.config.setdefault('jwt_alg', jwt_alg)
        self.config.setdefault('jwt_exp', jwt_exp)

    def create_expires_generator(self, app):
        """Create a generator function for generating ``expires_in`` value.
        Developers can re-implement this method with a subclass if other means
        required. The default expires_in value is defined by ``grant_type``,
        different ``grant_type`` has different value. It can be configured
        with::

            OAUTH2_EXPIRES_IN = {
                'authorization_code': 864000,
                'urn:ietf:params:oauth:grant-type:jwt-bearer': 3600,
            }
        """
        expires_conf = {}
        expires_conf.update(GRANT_TYPES_EXPIRES)
        expires_conf.update(app.config.get('OAUTH2_EXPIRES_IN', {}))

        def expires_in(client, grant_type):
            conf_key = 'OAUTH2_EXPIRES_{}'.format(grant_type.upper())
            expires = app.config.get(conf_key)
            if expires:
                deprecate('Deprecate "{}".'.format(conf_key), '0.10', 'vpCH5', 'as')
                return expires
            return expires_conf.get(grant_type, BearerToken.DEFAULT_EXPIRES_IN)

        return expires_in

    def create_bearer_token_generator(self, app):
        """Create a generator function for generating ``token`` value. This
        method will create a Bearer Token generator with
        :class:`authlib.specs.rfc6750.BearerToken`. By default, it will not
        generate ``refresh_token``, which can be turn on by configuration
        ``OAUTH2_REFRESH_TOKEN_GENERATOR=True``.
        """
        access_token_generator = app.config.get(
            'OAUTH2_ACCESS_TOKEN_GENERATOR', True
        )

        if isinstance(access_token_generator, str):
            access_token_generator = import_string(access_token_generator)
        else:
            def access_token_generator():
                return generate_token(42)

        refresh_token_generator = app.config.get(
            'OAUTH2_REFRESH_TOKEN_GENERATOR', False
        )
        if isinstance(refresh_token_generator, str):
            refresh_token_generator = import_string(refresh_token_generator)
        elif refresh_token_generator is True:
            def refresh_token_generator():
                return generate_token(48)
        else:
            refresh_token_generator = None

        expires_generator = self.create_expires_generator(app)
        return BearerToken(
            access_token_generator,
            refresh_token_generator,
            expires_generator
        )

    def validate_authorization_request(self):  # pragma: no cover
        deprecate(
            'use `server.validate_consent_request(end_user=current_user)` instead',
            '0.8', link_uid='vAAUK', link_file='VAR')
        grant = self.get_authorization_grant(_create_oauth2_request(None))
        grant.validate_authorization_request()
        return grant

    def validate_consent_request(self, request=None, end_user=None):
        """Validate current HTTP request for authorization page. This page
        is designed for resource owner to grant or deny the authorization::

            @app.route('/authorize', methods=['GET'])
            def authorize():
                try:
                    grant = server.validate_consent_request(end_user=current_user)
                    return render_template(
                        'authorize.html',
                        grant=grant,
                        user=current_user
                    )
                except OAuth2Error as error:
                    return render_template(
                        'error.html',
                        error=error
                    )
        """
        req = _create_oauth2_request(request)
        grant = self.get_authorization_grant(req)
        grant.validate_authorization_request()
        if hasattr(grant, 'validate_prompt'):
            # prompt is designed for OpenID Connect
            grant.validate_prompt(end_user=end_user)
        if not hasattr(grant, 'prompt'):
            grant.prompt = None
        return grant

    def create_authorization_response(self, request=None, grant_user=None):
        """Create the HTTP response for authorization. If resource owner
        granted the authorization, pass the resource owner as the user
        parameter, otherwise None::

            @app.route('/authorize', methods=['POST'])
            def confirm_authorize():
                if request.form['confirm'] == 'ok':
                    grant_user = current_user
                else:
                    grant_user = None
                return server.create_authorization_response(grant_user=grant_user)
        """
        if request and not grant_user:  # pragma: no cover
            grant_user = request
            # prepare for next upgrade
            deprecate(
                'Use "create_authorization_response(grant_user=grant_user)" instead',
                '0.8', 'vAAUK', 'car'
            )
        status, body, headers = self.create_valid_authorization_response(
            _create_oauth2_request(None),
            grant_user=grant_user
        )
        if isinstance(body, dict):
            body = json.dumps(body)
        return Response(body, status=status, headers=headers)

    def create_token_response(self, request=None):
        """Create the HTTP response for token endpoint. It is ready to use, as
        simple as::

            @app.route('/token', methods=['POST'])
            def issue_token():
                return server.create_token_response()
        """
        req = _create_oauth2_request(request)
        status, body, headers = super(
            AuthorizationServer, self).create_token_response(req)
        return Response(json.dumps(body), status=status, headers=headers)

    def create_endpoint_response(self, name, request=None):
        req = _create_oauth2_request(request)
        status, body, headers = super(
            AuthorizationServer, self).create_endpoint_response(name, req)
        return Response(json.dumps(body), status=status, headers=headers)

    def create_revocation_response(self):  # pragma: no cover
        deprecate(
            'Use `create_endpoint_response("revocation")` instead',
            '0.8', 'vAAUK', 're'
        )
        return self.create_endpoint_response('revocation')


def _create_oauth2_request(request):
    q = request or flask_req
    if q.method == 'POST':
        body = q.form.to_dict(flat=True)
    else:
        body = None

    return OAuth2Request(
        q.method,
        q.url,
        body,
        q.headers
    )
