.. _flask_oauth2_server:

Flask OAuth 2.0 Server
======================

.. meta::
    :description: How to create an OAuth 2.0 server in Flask with Authlib.
        And understand how OAuth 2.0 works.

In this section, we will learn how to create an OAuth 2.0 server in Flask.
An OAuth 2.0 provider contains two servers:

- Authorization Server: to issue access tokens
- Resources Server: to serve your users' resources

Here is an `example of OAuth 2.0 server <https://github.com/authlib/example-oauth2-server>`_.

.. note::

    If you are developing on your localhost, remember to set the environment
    variable::

        export AUTHLIB_INSECURE_TRANSPORT=true

Authorization Server
--------------------

The Authorization Server provides several endpoints for authorization, issuing
tokens, refreshing tokens and revoking tokens. When the resource owner (user)
grants the authorization, this server will issue an access token to the client.

Before creating the authorization server, we need to understand several
concepts:

Resource Owner
~~~~~~~~~~~~~~

Resource Owner is the user who is using your service. A resource owner can
log in your website with username/email and password, or other methods.

A resource owner SHOULD implement ``get_user_id()`` method::

    class User(db.Model):
        id = db.Column(db.Integer, primary_key=True)

        def get_user_id(self):
            return self.id

Client
~~~~~~

A client is an application making protected resource requests on behalf of the
resource owner and with its authorization. It contains at least three
information:

- Client Type, confidential or public
- Client Identifier, usually called **client_id**
- Client Password, usually called **client_secret**

Authlib has provided a mixin for SQLAlchemy, define the client with this mixin::

    from authlib.flask.oauth2.sqla import OAuth2ClientMixin

    class Client(db.Model, OAuth2ClientMixin):
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(
            db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
        )
        user = db.relationship('User')

A client is registered by a user (developer) on your website. Get a deep
inside with :class:`~authlib.specs.rfc6749.ClientMixin` API reference.

Token
~~~~~

.. note::

    Only Bearer Token is supported by now. MAC Token is still under drafts,
    it will be available when it goes into RFC.

Tokens are used to access the users' resources. A token is issued with a
valid duration, limited scopes and etc. It contains at least:

- **access_token**: a token to authorize the http requests.
- **refresh_token**: (optional) a token to exchange a new access token
- **client_id**: this token is issued to which client
- **expires_at**: when will this token expired
- **scope**: a limited scope of resources that this token can access

With the SQLAlchemy mixin provided by Authlib::

    from authlib.flask.oauth2.sqla import OAuth2TokenMixin

    class Token(db.Model, OAuth2TokenMixin):
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(
            db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
        )
        user = db.relationship('User')

A token is associated with a resource owner. There is no certain name for
it, here we call it ``user``, but it can be anything else.

Define Server
~~~~~~~~~~~~~

Authlib provides a ready to use :class:`~authlib.flask.oauth2.AuthorizationServer`
which has built-in tools to handle requests and responses::

    from authlib.flask.oauth2 import AuthorizationServer

    def query_client(client_id):
        return Client.query.filter_by(client_id=client_id).first()

    def save_token(token, request):
        if request.user:
            user_id = request.user.get_user_id()
        else:
            # client_credentials grant_type
            user_id = request.client.user_id
            # or, depending on how you treat client_credential
            user_id = None
        item = Token(
            client_id=request.client.client_id,
            user_id=user_id,
            **token
        )
        db.session.add(item)
        db.session.commit()

    # or with the helper
    from authlib.flask.oauth2.sqla import (
        create_query_client_func,
        create_save_token_func
    )
    query_client = create_query_client_func(db.session, Client)
    save_token = create_save_token_func(db.session, Token)

    server = AuthorizationServer(
        app, query_client=query_client, save_token=save_token
    )

It can also be initialized lazily with init_app::

    server = AuthorizationServer()
    server.init_app(app, query_client=query_client, save_token=save_token)

It works well without configuration. However, it can be configured with these
settings:

================================== ===============================================
OAUTH2_EXPIRES_AUTHORIZATION_CODE  Token ``expires_in`` by ``authorization_code``
                                   grant, default is 864000
OAUTH2_EXPIRES_IMPLICIT            Token ``expires_in`` by ``implicit``
                                   grant, default is 3600
OAUTH2_EXPIRES_PASSWORD            Token ``expires_in`` by ``password``
                                   grant, default is 864000
OAUTH2_EXPIRES_CLIENT_CREDENTIAL   Token ``expires_in`` by ``client_credential``
                                   grant, default is 864000
OAUTH2_ACCESS_TOKEN_GENERATOR      A string of module path for importing a
                                   function to generate ``access_token``
OAUTH2_REFRESH_TOKEN_GENERATOR     A string of module path for importing a
                                   function to generate ``refresh_token``. It can
                                   also be ``True/False``
OAUTH2_ERROR_URIS                  A list of tuple for (``error``, ``error_uri``)
================================== ===============================================

Now define an endpoint for authorization. This endpoint is used by
``authorization_code`` and ``implicit`` grants::

    from flask import request, render_template
    from your_project.auth import current_user

    @app.route('/oauth/authorize', methods=['GET', 'POST'])
    def authorize():
        # Login is required since we need to know the current resource owner.
        # It can be done with a redirection to the login page, or a login
        # form on this authorization page.
        if request.method == 'GET':
            grant = server.validate_consent_request(end_user=current_user)
            return render_template(
                'authorize.html',
                grant=grant,
                user=current_user,
            )
        confirmed = request.form['confirm']
        if confirmed:
            # granted by resource owner
            return server.create_authorization_response(current_user)
        # denied by resource owner
        return server.create_authorization_response(None)

This is a simple demo, the real case should be more complex. There is a demo
in `authlib/playground`_, get a real taste with Authlib Playground.

The token endpoint is much easier::

    @app.route('/oauth/token', methods=['POST'])
    def issue_token():
        return server.create_token_response()

However, the routes will not work properly. We need to register supported
grants for them.

.. _`authlib/playground`: https://github.com/authlib/playground

Register Grants
---------------

.. module:: authlib.specs.rfc6749.grants

There are four grant types defined by RFC6749, you can also create your own
extended grant. Register the supported grant types to the authorization server.

.. _flask_oauth2_code_grant:

Authorization Code Grant
~~~~~~~~~~~~~~~~~~~~~~~~

Authorization Code Grant is a very common grant type, it is supported by almost
every OAuth 2 providers. It uses an authorization code to exchange access
token. In this case, we need a place to store the authorization code. It can be
kept in a database or a cache like redis. Here is a SQLAlchemy mixin for
**AuthorizationCode**::

    from authlib.flask.oauth2.sqla import OAuth2AuthorizationCodeMixin

    class AuthorizationCode(db.Model, OAuth2AuthorizationCodeMixin):
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(
            db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
        )
        user = db.relationship('User')

Implement this grant by subclass :class:`AuthorizationCodeGrant`::

    from authlib.specs.rfc6749 import grants
    from authlib.common.security import generate_token

    class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
        def create_authorization_code(self, client, grant_user, request):
            # you can use other method to generate this code
            code = generate_token(48)
            item = AuthorizationCode(
                code=code,
                client_id=client.client_id,
                redirect_uri=request.redirect_uri,
                scope=request.scope,
                user_id=grant_user.get_user_id(),
            )
            db.session.add(item)
            db.session.commit()
            return code

        def parse_authorization_code(self, code, client):
            item = AuthorizationCode.query.filter_by(
                code=code, client_id=client.client_id).first()
            if item and not item.is_expired():
                return item

        def delete_authorization_code(self, authorization_code):
            db.session.delete(authorization_code)
            db.session.commit()

        def authenticate_user(self, authorization_code):
            return User.query.get(authorization_code.user_id)

    # register it to grant endpoint
    server.register_grant(AuthorizationCodeGrant)

.. note:: AuthorizationCodeGrant is the most complex grant.

Implicit Grant
~~~~~~~~~~~~~~

The implicit grant type is usually used in a browser, when resource
owner granted the access, access token is issued in the redirect URI,
there is no missing implementation, which means it can be easily registered
with::

    from authlib.specs.rfc6749 import grants

    # register it to grant endpoint
    server.register_grant(grants.ImplicitGrant)

Implicit Grant is used by **public** client which has no **client_secret**.

Resource Owner Password Credentials Grant
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Resource owner uses his username and password to exchange an access token,
this grant type should be used only when the client is trustworthy, implement
it with a subclass of :class:`ResourceOwnerPasswordCredentialsGrant`::

    from authlib.specs.rfc6749 import grants

    class PasswordGrant(grants.ResourceOwnerPasswordCredentialsGrant):
        def authenticate_user(self, username, password):
            user = User.query.filter_by(username=username).first()
            if user.check_password(password):
                return user

    # register it to grant endpoint
    server.register_grant(PasswordGrant)

Client Credentials Grant
~~~~~~~~~~~~~~~~~~~~~~~~

Client credentials grant type can access public resources and MAYBE the
client's creator's resources, depending on how you issue tokens to this
grant type. It can be easily registered with::

    from authlib.specs.rfc6749 import grants

    # register it to grant endpoint
    server.register_grant(grants.ClientCredentialsGrant)

Refresh Token
-------------

Many OAuth 2 providers haven't implemented refresh token endpoint. Authlib
provides it as a grant type, implement it with a subclass of
:class:`RefreshTokenGrant`::

    from authlib.specs.rfc6749 import grants

    class RefreshTokenGrant(grants.RefreshTokenGrant):
        def authenticate_refresh_token(self, refresh_token):
            item = Token.query.filter_by(refresh_token=refresh_token).first()
            # define is_refresh_token_expired by yourself
            if item and not item.is_refresh_token_expired():
                return item

        def authenticate_user(self, credential):
            return User.query.get(credential.user_id)

    # register it to grant endpoint
    server.register_grant(RefreshTokenGrant)


Other Token Endpoints
---------------------

Flask OAuth 2.0 authorization server has a method to register other token
endpoints: ``authorization_server.register_endpoint``. Find the available
endpoints:

- :ref:`register_revocation_endpoint`
- :ref:`register_introspection_endpoint`

.. _flask_oauth2_resource_protector:

Protect Resources
-----------------

Protect users resources, so that only the authorized clients with the
authorized access token can access the given scope resources.

A resource server can be a different server other than the authorization
server. Here is the way to protect your users' resources::

    from flask import jsonify
    from authlib.flask.oauth2 import ResourceProtector, current_token
    from authlib.specs.rfc6750 import BearerTokenValidator

    class MyBearerTokenValidator(BearerTokenValidator):
        def authenticate_token(self, token_string):
            return Token.query.filter_by(access_token=token_string).first()

        def request_invalid(self, request):
            return False

        def token_revoked(self, token):
            return token.revoked

    # only bearer token is supported currently
    ResourceProtector.register_token_validator(MyBearerTokenValidator())

    # you can also create BearerTokenValidator with shortcut
    from authlib.flask.oauth2.sqla import create_bearer_token_validator

    BearerTokenValidator = create_bearer_token_validator(db.session, Token)
    ResourceProtector.register_token_validator(BearerTokenValidator())

    require_oauth = ResourceProtector()

    @app.route('/user')
    @require_oauth('profile')
    def user_profile():
        user = current_token.user
        return jsonify(user)

If the resource is not protected by a scope, use ``None``::

    @app.route('/user')
    @require_oauth()
    def user_profile():
        user = current_token.user
        return jsonify(user)

    # or with None

    @app.route('/user')
    @require_oauth(None)
    def user_profile():
        user = current_token.user
        return jsonify(user)

The ``current_token`` is a proxy to the Token model you have defined above.
Since there is a ``user`` relationship on the Token model, we can access this
``user`` with ``current_token.user``.

MethodView & Flask-Restful
~~~~~~~~~~~~~~~~~~~~~~~~~~~

You can also use the ``require_oauth`` decorator in ``flask.views.MethodView``
and ``flask_restful.Resource``::

    from flask.views import MethodView

    class UserAPI(MethodView):
        decorators = [require_oauth('profile')]


    from flask_restful import Resource

    class UserAPI(Resource):
        method_decorators = [require_oauth('profile')]


Register Error URIs
-------------------

To create a better developer experience for debugging, it is suggested that
you creating some documentation for errors. Here is a list of built-in
:ref:`specs/rfc6949-errors`.

You can design a documentation page with a description of each error. For
instance, there is a web page for ``invalid_client``::

   https://developer.your-company.com/errors#invalid-client

In this case, you can register the error URI with ``OAUTH2_ERROR_URIS``
configuration::

   OAUTH2_ERROR_URIS = [
      ('invalid_client', 'https://developer.your-company.com/errors#invalid-client'),
      # other error URIs
   ]


.. _flask_oauth2_custom_grant_types:

Custom Grant Types
------------------

It is also possible to create your own grant types. In Authlib, a **Grant**
supports two endpoints:

1. Authorization Endpoint: which can handle requests with ``response_type``.
2. Token Endpoint: which is the endpoint to issue tokens.

Creating a custom grant type with **BaseGrant**::

    from authlib.specs.rfc6749 import grants


    class MyCustomGrant(grants.BaseGrant):
        AUTHORIZATION_ENDPOINT = True  # if you want to support it
        TOKEN_ENDPOINT = True  # if you want to support it

        @classmethod
        def check_authorization_endpoint(cls, request):
            # can MyCustomGrant handle this request for TOKEN_ENDPOINT
            return True or False

        @classmethod
        def check_token_endpoint(cls, request):
            # can MyCustomGrant handle this request for TOKEN_ENDPOINT
            return True or False

        def validate_authorization_request(self):
            # only needed if AUTHORIZATION_ENDPOINT = True

        def create_authorization_response(self, grant_user):
            # only needed if AUTHORIZATION_ENDPOINT = True

        def validate_token_request(self):
            # only needed if TOKEN_ENDPOINT = True

        def create_token_response(self):
            # only needed if TOKEN_ENDPOINT = True

For a better understanding, you can read the source code of the built-in
grant types.
