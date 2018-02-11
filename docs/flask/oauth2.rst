.. _flask_oauth2_server:

Flask OAuth 2 Server
====================

.. meta::
    :description: How to create an OAuth 2 server in Flask with Authlib.
        And understand how OAuth 2 works.

Implement OAuth 2 provider in Flask. An OAuth 2 provider contains two servers:

- Authorization Server: to issue access tokens
- Resources Server: to serve your users' resources

.. note::

    Only Bearer Token is supported by now. MAC Token is still under drafts,
    it will be available when it goes into RFC.

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

    # or with the helper
    from authlib.flask.oauth2.sqla import create_query_client_func
    query_client = create_query_client_func(db.session, Client)

    server = AuthorizationServer(app, query_client=query_client)

It can also be initialized lazily with init_app::

    server = AuthorizationServer()
    server.init_app(app, query_client=query_client)

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
            grant = server.validate_authorization_request()
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

The revocation endpoint is optional, if revocation feature is wanted::

    @app.route('/oauth/revoke', methods=['POST'])
    def revoke_token():
        return server.create_revocation_response()

However, the routes will not work properly. We need to register supported
grants for them.

.. _`authlib/playground`: https://github.com/authlib/playground

Register Grants
---------------

.. module:: authlib.specs.rfc6749.grants

There are four grant types defined by RFC6749, you can also create your own
extended grant. Register the supported grant types to the authorization server.

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

    from authlib.specs.rfc6749.grants import (
        AuthorizationCodeGrant as _AuthorizationCodeGrant
    )
    from authlib.common.security import generate_token

    class AuthorizationCodeGrant(_AuthorizationCodeGrant):
        def create_authorization_code(self, client, grant_user, **kwargs):
            # you can use other method to generate this code
            code = generate_token(48)
            item = AuthorizationCode(
                code=code,
                client_id=client.client_id,
                redirect_uri=kwargs.get('redirect_uri', ''),
                scope=kwargs.get('scope', ''),
                user_id=grant_user.id,
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

        def create_access_token(self, token, client, authorization_code):
            item = Token(
                client_id=client.client_id,
                user_id=authorization_code.user_id,
                **token
            )
            db.session.add(item)
            db.session.commit()
            # we can add more data into token
            token['user_id'] = authorization_code.user_id

    # register it to grant endpoint
    server.register_grant_endpoint(AuthorizationCodeGrant)

.. note:: AuthorizationCodeGrant is the most complex grant.

Implicit Grant
~~~~~~~~~~~~~~

The implicit grant type is usually used in a browser, when resource
owner granted the access, access token is issued in the redirect URI,
implement it with a subclass of :class:`ImplicitGrant`::

    from authlib.specs.rfc6749.grants import (
        ImplicitGrant as _ImplicitGrant
    )

    class ImplicitGrant(_ImplicitGrant):
        def create_access_token(self, token, client, grant_user, **kwargs):
            item = Token(
                client_id=client.client_id,
                user_id=grant_user.id,
                **token
            )
            db.session.add(item)
            db.session.commit()

    # register it to grant endpoint
    server.register_grant_endpoint(ImplicitGrant)

Implicit Grant is used by **public** client which has no **client_secret**.

Resource Owner Password Credentials Grant
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Resource owner uses his username and password to exchange an access token,
this grant type should be used only when the client is trustworthy, implement
it with a subclass of :class:`ResourceOwnerPasswordCredentialsGrant`::

    from authlib.specs.rfc6749.grants import (
        ResourceOwnerPasswordCredentialsGrant as _PasswordGrant
    )

    class PasswordGrant(_PasswordGrant):
        def authenticate_user(self, username, password):
            user = User.query.filter_by(username=username).first()
            if user.check_password(password):
                return user

        def create_access_token(self, token, client, user, **kwargs):
            item = Token(
                client_id=client.client_id,
                user_id=user.id,
                **token
            )
            db.session.add(item)
            db.session.commit()

    # register it to grant endpoint
    server.register_grant_endpoint(PasswordGrant)

Client Credentials Grant
~~~~~~~~~~~~~~~~~~~~~~~~

Client credentials grant type can access public resources and the client's
creator's resources, implement it with a subclass of
:class:`ClientCredentialsGrant`::

    from authlib.specs.rfc6749.grants import (
        ClientCredentialsGrant as _ClientCredentialsGrant
    )

    class ClientCredentialsGrant(_ClientCredentialsGrant):
        def create_access_token(self, token, client):
            item = Token(
                client_id=client.client_id,
                user_id=client.user_id,
                **token
            )
            db.session.add(item)
            db.session.commit()

    # register it to grant endpoint
    server.register_grant_endpoint(ClientCredentialsGrant)

Refresh Token
-------------

Many OAuth 2 providers haven't implemented refresh token endpoint. Authlib
provides it as a grant type, implement it with a subclass of
:class:`RefreshTokenGrant`::

    from authlib.specs.rfc6749.grants import (
        RefreshTokenGrant as _RefreshTokenGrant
    )

    class RefreshTokenGrant(_RefreshTokenGrant):
        def authenticate_token(self, refresh_token):
            item = Token.query.filter_by(refresh_token=refresh_token).first()
            # define is_refresh_token_expired by yourself
            if item and not item.is_refresh_token_expired():
                return item

        def create_access_token(self, token, authenticated_token):
            # issue a new token to replace the old one, you can also update
            # the ``authenticated_token`` instead of issuing a new one
            item = Token(
                client_id=authenticated_token.client_id,
                user_id=authenticated_token.user_id,
                **token
            )
            db.session.add(item)
            db.session.delete(authenticated_token)
            db.session.commit()


Token Revocation
----------------

RFC7009_ defined a way to revoke a token. To implement the token revocation
endpoint, subclass **RevocationEndpoint** and define the missing methods::

    from authlib.specs.rfc7009 import RevocationEndpoint as _RevocationEndpoint

    class RevocationEndpoint(_RevocationEndpoint):
        def query_token(self, token, token_type_hint, client):
            q = Token.query.filter_by(client_id=client.client_id)
            if token_type_hint == 'access_token':
                return q.filter_by(access_token=token).first()
            elif token_type_hint == 'refresh_token':
                return q.filter_by(refresh_token=token).first()
            # without token_type_hint
            item = q.filter_by(access_token=token).first()
            if item:
                return item
            return q.filter_by(refresh_token=token).first()

        def invalidate_token(self, token):
            db.session.delete(token)
            db.session.commit()

    # register it to authorization server
    server.register_revoke_token_endpoint(RevocationEndpoint)

.. _RFC7009: https://tools.ietf.org/html/rfc7009

Protect Resources
-----------------

Protect users resources, so that only the authorized clients with the
authorized access token can access the given scope resources.

A resource server can be a different server other than the authorization
server. Here is the way to protect your users' resources::

    from flask import jsonify
    from authlib.flask.oauth2 import ResourceProtector, current_token

    def query_token(access_token=access_token):
        return Token.query.filter_by(access_token=access_token).first()

    # or with the helper
    from authlib.flask.oauth2.sqla import create_query_token_func
    query_token = create_query_token_func(db.session, Token)

    require_oauth = ResourceProtector(query_token)

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


Create Custom Grant Types
-------------------------

It is possible to create your own grant types.

(TODO)
