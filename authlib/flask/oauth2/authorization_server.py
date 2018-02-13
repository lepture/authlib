from werkzeug.utils import import_string
from flask import request, Response, json
from authlib.specs.rfc6749 import (
    OAuth2Request,
    register_error_uri,
    AuthorizationServer as _AuthorizationServer,
)
from authlib.specs.rfc6750 import BearerToken
from authlib.common.security import generate_token
from authlib.deprecate import deprecate

GRANT_TYPES_EXPIRES = {
    'authorization_code': 864000,
    'implicit': 3600,
    'password': 864000,
    'client_credential': 864000
}


class AuthorizationServer(_AuthorizationServer):
    """Flask implementation of :class:`authlib.rfc6749.AuthorizationServer`.
    Initialize it with a client model class and Flask app instance::

        def query_client(client_id):
            return Client.query.filter_by(client_id=client_id).first()

        server = AuthorizationServer(app, query_client)
        # or initialize lazily
        server = AuthorizationServer()
        server.init_app(app, query_client)
    """
    def __init__(self, app=None, query_client=None):
        query_client = _compatible_query_client(query_client)
        super(AuthorizationServer, self).__init__(query_client, None)
        self.revoke_token_endpoint = None
        self.app = app
        if app is not None:
            self.init_app(app)

    def register_revoke_token_endpoint(self, cls):
        """Add revoke token support for authorization server. Revoke token is
        defined by RFC7009_, implemented with
        :class:`authlib.specs.rfc7009.RevocationEndpoint`.

        .. _RFC7009: https://tools.ietf.org/html/rfc7009
        """
        self.revoke_token_endpoint = cls

    def init_app(self, app, query_client=None):
        """Initialize later with Flask app instance."""
        query_client = _compatible_query_client(query_client)
        if query_client is not None:
            self.query_client = query_client
        for k in GRANT_TYPES_EXPIRES:
            conf_key = 'OAUTH2_EXPIRES_{}'.format(k.upper())
            app.config.setdefault(conf_key, GRANT_TYPES_EXPIRES[k])

        # register error uri
        error_uris = app.config.get('OAUTH2_ERROR_URIS')
        if error_uris:
            for k, v in error_uris:
                register_error_uri(k, v)

        self.app = app
        self.token_generator = self.create_bearer_token_generator(app)

    def create_expires_generator(self, app):
        """Create a generator function for generating ``expires_in`` value.
        Developers can re-implement this method with a subclass if other means
        required. The default expires_in value is defined by ``grant_type``,
        different ``grant_type`` has different value. It can be configured
        with: ``OAUTH2_EXPIRES_{{grant_type|upper}}``.
        """

        def expires_in(client, grant_type):
            conf_key = 'OAUTH2_EXPIRES_{}'.format(grant_type.upper())
            return app.config.get(conf_key, BearerToken.DEFAULT_EXPIRES_IN)

        return expires_in

    def create_bearer_token_generator(self, app):
        """Create a generator function for generating ``token`` value. This
        method will create a Bearer Token generator with
        :class:`authlib.specs.rfc6750.BearerToken`. By default, it will not
        generate ``refresh_token``, which can be turn on by configuration
        ``OAUTH2_REFRESH_TOKEN_GENERATOR=True``.
        """
        access_token_generator = app.config.get(
            'OAUTH2_ACCESS_TOKEN_GENERATOR',
            True
        )

        if isinstance(access_token_generator, str):
            access_token_generator = import_string(access_token_generator)
        else:
            def access_token_generator():
                return generate_token(42)

        refresh_token_generator = app.config.get(
            'OAUTH2_REFRESH_TOKEN_GENERATOR',
            False
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

    def validate_authorization_request(self):
        """Validate current HTTP request for authorization page. This page
        is designed for resource owner to grant or deny the authorization::

            @app.route('/authorize', methods=['GET'])
            def authorize():
                try:
                    grant = server.validate_authorization_request()
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
        grant = self.get_authorization_grant(_create_oauth2_request())
        grant.validate_authorization_request()
        return grant

    def create_authorization_response(self, grant_user=None):
        """Create the HTTP response for authorization. If resource owner
        granted the authorization, pass the resource owner as the user
        parameter, otherwise None::

            @app.route('/authorize', methods=['POST'])
            def confirm_authorize():
                if request.form['confirm'] == 'ok':
                    grant_user = current_user
                else:
                    grant_user = None
                return server.create_authorization_response(grant_user)
        """
        status, body, headers = self.create_valid_authorization_response(
            _create_oauth2_request(),
            grant_user=grant_user
        )
        if isinstance(body, dict):
            body = json.dumps(body)
        return Response(body, status=status, headers=headers)

    def create_token_response(self):
        """Create the HTTP response for token endpoint. It is ready to use, as
        simple as::

            @app.route('/token', methods=['POST'])
            def issue_token():
                return server.create_token_response()
        """
        req = _create_oauth2_request()
        status, body, headers = self.create_valid_token_response(req)
        return Response(json.dumps(body), status=status, headers=headers)

    def create_revocation_response(self):
        """Create HTTP response for revocation endpoint.
        :meth:`register_revoke_token_endpoint` is required before using this
        method. It is ready to use, as simple as::

            @app.route('/token/revoke', methods=['POST'])
            def revoke_token():
                return server.create_revocation_response()
        """
        req = _create_oauth2_request()
        endpoint = self.revoke_token_endpoint(req, self.query_client)
        status, body, headers = endpoint.create_revocation_response()
        return Response(json.dumps(body), status=status, headers=headers)


def _compatible_query_client(query_client):
    if query_client and hasattr(query_client, 'get_by_client_id'):
        message = (
            'client_model is deprecated.\n\n'
            'Please read: <https://github.com/lepture/authlib/issues/27>'
        )
        deprecate(message, '0.7')
        query_client = query_client.get_by_client_id
    return query_client


def _create_oauth2_request():
    if request.method == 'POST':
        body = request.form.to_dict(flat=True)
    else:
        body = None

    return OAuth2Request(
        request.method,
        request.url,
        body,
        request.headers
    )
