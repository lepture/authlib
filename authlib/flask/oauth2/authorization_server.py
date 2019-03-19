from werkzeug.utils import import_string
from flask import Response, json
from authlib.oauth2 import (
    OAuth2Request,
    ClientAuthentication,
    AuthorizationServer as _AuthorizationServer,
)
from authlib.oauth2.rfc6750 import BearerToken
from authlib.common.security import generate_token
from authlib.common.encoding import to_unicode
from .signals import client_authenticated, token_revoked
from ..helpers import create_oauth_request

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
        if app is not None:
            self.init_app(app)

    def init_app(self, app, query_client=None, save_token=None):
        """Initialize later with Flask app instance."""
        if query_client is not None:
            self.query_client = query_client
            self.authenticate_client = ClientAuthentication(query_client)
        if save_token is not None:
            self.save_token = save_token

        self.config.setdefault('error_uris', app.config.get('OAUTH2_ERROR_URIS'))
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

    def create_oauth2_request(self, request):
        return create_oauth_request(request, OAuth2Request)

    def handle_response(self, status_code, payload, headers):
        if isinstance(payload, dict):
            payload = json.dumps(payload)
        return Response(payload, status=status_code, headers=headers)

    def send_signal(self, name, *args, **kwargs):
        if name == 'after_authenticate_client':
            client_authenticated.send(self, *args, **kwargs)
        elif name == 'after_revoke_token':
            token_revoked.send(self, *args, **kwargs)

    def create_token_expires_in_generator(self, app):
        """Create a generator function for generating ``expires_in`` value.
        Developers can re-implement this method with a subclass if other means
        required. The default expires_in value is defined by ``grant_type``,
        different ``grant_type`` has different value. It can be configured
        with::

            OAUTH2_TOKEN_EXPIRES_IN = {
                'authorization_code': 864000,
                'urn:ietf:params:oauth:grant-type:jwt-bearer': 3600,
            }
        """
        expires_conf = app.config.get('OAUTH2_TOKEN_EXPIRES_IN')
        return create_token_expires_in_generator(expires_conf)

    def create_bearer_token_generator(self, app):
        """Create a generator function for generating ``token`` value. This
        method will create a Bearer Token generator with
        :class:`authlib.oauth2.rfc6750.BearerToken`. By default, it will not
        generate ``refresh_token``, which can be turn on by configuration
        ``OAUTH2_REFRESH_TOKEN_GENERATOR=True``.
        """
        conf = app.config.get('OAUTH2_ACCESS_TOKEN_GENERATOR', True)
        access_token_generator = create_token_generator(conf, 42)

        conf = app.config.get('OAUTH2_REFRESH_TOKEN_GENERATOR', False)
        refresh_token_generator = create_token_generator(conf, 48)

        expires_generator = self.create_token_expires_in_generator(app)
        return BearerToken(
            access_token_generator,
            refresh_token_generator,
            expires_generator
        )

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
        req = self.create_oauth2_request(request)
        req.user = end_user

        grant = self.get_authorization_grant(req)
        grant.validate_consent_request()
        if not hasattr(grant, 'prompt'):
            grant.prompt = None
        return grant


def create_token_expires_in_generator(expires_in_conf=None):
    data = {}
    data.update(GRANT_TYPES_EXPIRES)
    if expires_in_conf:
        data.update(expires_in_conf)

    def expires_in(client, grant_type):
        return data.get(grant_type, BearerToken.DEFAULT_EXPIRES_IN)

    return expires_in


def create_token_generator(token_generator_conf, length=42):
    if callable(token_generator_conf):
        return token_generator_conf

    if isinstance(token_generator_conf, str):
        return import_string(token_generator_conf)
    elif token_generator_conf is True:
        def token_generator(*args, **kwargs):
            return generate_token(length)
        return token_generator
