.. _flask_oauth1_server:

Flask OAuth 1.0 Server
======================

.. meta::
    :description: How to create an OAuth 1.0 server in Flask with Authlib.
        And understand how OAuth 1.0 works.

Implement OAuth 1.0 provider in Flask. An OAuth 1 provider contains two servers:

- Authorization Server: to issue access tokens
- Resources Server: to serve your users' resources


.. note::

    If you are developing on your localhost, remember to set the environment
    variable::

        export AUTHLIB_INSECURE_TRANSPORT=true

Authorization Server
--------------------

The Authorization Server provides several endpoints for temporary credentials,
authorization, and issuing token credentials. When the resource owner (user)
grants the authorization, this server will issue a token credential to the
client.

Resource Owner
~~~~~~~~~~~~~~

Resource Owner is the user who is using your service. A resource owner can
log in your website with username/email and password, or other methods.

A resource owner MUST implement ``get_user_id()`` method::

    class User(db.Model):
        id = db.Column(db.Integer, primary_key=True)

        def get_user_id(self):
            return self.id

Client
~~~~~~

A client is an application making protected resource requests on behalf of the
resource owner and with its authorization. It contains at least three
information:

- Client Identifier, usually called **client_id**
- Client Password, usually called **client_secret**
- Client RSA Public Key (if RSA-SHA1 signature method supported)

Authlib has provided a mixin for SQLAlchemy, define the client with this mixin::

    from authlib.flask.oauth1.sqla import OAuth1ClientMixin

    class Client(db.Model, OAuth1ClientMixin):
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(
            db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
        )
        user = db.relationship('User')

A client is registered by a user (developer) on your website. Get a deep
inside with :class:`~authlib.specs.rfc5849.ClientMixin` API reference.

Temporary Credentials
~~~~~~~~~~~~~~~~~~~~~

A temporary credential is used to exchange a token credential. It is also
known as "request token and secret". Since it is temporary, it is better to
save them into cache instead of database. A cache instance should has these
methods:

- ``.get(key)``
- ``.set(key, value, expires=None)``
- ``.delete(key)``

A cache can be a memcache, redis or something else. If cache is not available,
there is also a SQLAlchemy mixin::

    from authlib.flask.oauth1.sqla import OAuth1TemporaryCredentialMixin

    class TemporaryCredential(db.Model, OAuth1TemporaryCredentialMixin):
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(
            db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
        )
        user = db.relationship('User')

To make a Temporary Credentials model yourself, get more information with
:class:`~authlib.specs.rfc5849.ClientMixin` API reference.

Token Credentials
~~~~~~~~~~~~~~~~~

A token credential is used to access resource owners' resources. Unlike
OAuth 2, the token credential will not expire in OAuth 1. This token credentials
are supposed to be saved into a persist database rather than a cache.

Here is a SQLAlchemy mixin for easy integration::

    from authlib.flask.oauth1.sqla import OAuth1TokenCredentialMixin

    class TokenCredential(db.Model, OAuth1TokenCredentialMixin):
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(
            db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
        )
        user = db.relationship('User')

    def set_user_id(self, user_id):
        self.user_id = user_id

If SQLAlchemy is not what you want, read the API reference of
:class:`~authlib.specs.rfc5849.TokenCredentialMixin` and implement the missing
methods.

Timestamp and Nonce
~~~~~~~~~~~~~~~~~~~

The nonce value MUST be unique across all requests with the same timestamp,
client credentials, and token combinations. Authlib Flask integration has a
built-in validation with cache.

If cache is not available, there is also a SQLAlchemy mixin::

    from authlib.flask.oauth1.sqla import OAuth1TokenCredentialMixin

    class TimestampNonce(db.Model, OAuth1TokenCredentialMixin)
        id = db.Column(db.Integer, primary_key=True)


Define A Server
~~~~~~~~~~~~~~~

Authlib provides a ready to use :class:`~authlib.flask.oauth1.AuthorizationServer`
which has built-in tools to handle requests and responses::

    from authlib.flask.oauth1 import AuthorizationServer
    from authlib.flask.oauth1.sqla import create_query_client_func

    query_client = create_query_client_func(db.session, Client)
    server = AuthorizationServer(app, query_client=query_client)

It can also be initialized lazily with init_app::

    server = AuthorizationServer()
    server.init_app(app, query_client=query_client)

It is strongly suggested that you use a cache. In this way, you
don't have to re-implement a lot of the missing methods.

There are other configurations. It works well without any changes. Here is a
list of them:

================================== ===============================================
OAUTH1_TOKEN_GENERATOR             A string of module path for importing a
                                   function to generate ``oauth_token``
OAUTH1_TOKEN_SECRET_GENERATOR      A string of module path for importing a
                                   function to generate ``oauth_token_secret``.
OAUTH1_TOKEN_LENGTH                If ``OAUTH1_TOKEN_GENERATOR`` is not
                                   configured, a random function will generate
                                   the given length of ``oauth_token``. Default
                                   value is ``42``.
OAUTH1_TOKEN_SECRET_LENGTH         A random function will generate the given
                                   length of ``oauth_token_secret``. Default
                                   value is ``48``.
================================== ===============================================

These configurations are used to create the ``token_generator`` function. But
you can pass the ``token_generator`` when initializing the AuthorizationServer::

    def token_generator():
        return {
            'oauth_token': random_string(20),
            'oauth_token_secret': random_string(46)
        }

    server = AuthorizationServer(
        app,
        query_client=query_client,
        token_generator=token_generator
    )

Server Hooks
~~~~~~~~~~~~

There are missing hooks that should be ``register_hook`` to AuthorizationServer.
There are helper functions for registering hooks. If cache is available, you
can take the advantage with::

    from authlib.flask.oauth1.cache import (
        register_nonce_hooks,
        register_temporary_credential_hooks
    )
    from authlib.flask.oauth1.sqla import register_token_credential_hooks

    register_nonce_hooks(server, cache)
    register_temporary_credential_hooks(server, cache)
    register_token_credential_hooks(server, db.session, TokenCredential)

If cache is not available, here are the helpers for SQLAlchemy::

    from authlib.flask.oauth1.sqla import (
        register_nonce_hooks,
        register_temporary_credential_hooks,
        register_token_credential_hooks
    )

    register_nonce_hooks(server, db.session, TimestampNonce)
    register_temporary_credential_hooks(server, db.session, TemporaryCredential)
    register_token_credential_hooks(server, db.session, TokenCredential)


Server Implementation
~~~~~~~~~~~~~~~~~~~~~

It is ready to create the endpoints for authorization and issuing tokens.
Let's start with the temporary credentials endpoint, which is used for clients
to fetch a temporary credential::

    @app.route('/initiate', methods=['POST'])
    def initiate_temporary_credential():
        return server.create_temporary_credential_response()

The endpoint for resource owner authorization. OAuth 1 Client will redirect
user to this authorization page, so that resource owner can grant or deny this
request::

    @app.route('/authorize', methods=['GET', 'POST'])
    def authorize():
        # make sure that user is logged in for yourself
        if request.method == 'GET':
            try:
                req = server.check_authorization_request()
                return render_template('authorize.html', req=req)
            except OAuth1Error as error:
                return render_template('error.html', error=error)

        granted = request.form.get('granted')
        if granted:
            grant_user = current_user
        else:
            grant_user = None

        try:
            return server.create_authorization_response(grant_user)
        except OAuth1Error as error:
            return render_template('error.html', error=error)

Then the final token endpoint. OAuth 1 Client will use the given temporary
credential and the ``oauth_verifier`` authorized by resource owner to exchange
the token credential::

    @app.route('/token', methods=['POST'])
    def issue_token():
        return server.create_token_response()

Protect Resources
-----------------

Protect users resources, so that only the authorized clients with the
authorized access token can access the given scope resources.

A resource server can be a different server other than the authorization
server. Here is the way to protect your users' resources::

    from flask import jsonify
    from authlib.flask.oauth1 import ResourceProtector, current_credential
    from authlib.flask.oauth1.cache import create_exists_nonce_func
    from authlib.flask.oauth1.sqla import (
        create_query_client_func,
        create_query_token_func
    )

    query_client = create_query_client_func(db.session, Client)
    query_token = create_query_token_func(db.session, TokenCredential)
    exists_nonce = create_exists_nonce_func(cache)
    # OR: authlib.flask.oauth1.sqla.create_exists_nonce_func

    require_oauth = ResourceProtector(
        app, query_client=query_client,
        query_token=query_token,
        exists_nonce=exists_nonce,
    )
    # or initialize it lazily
    require_oauth = ResourceProtector()
    require_oauth.init_app(
        app,
        query_client=query_client,
        query_token=query_token,
        exists_nonce=exists_nonce,
    )

    @app.route('/user')
    @require_oauth()
    def user_profile():
        user = current_credential.user
        return jsonify(user)

The ``current_credential`` is a proxy to the Token model you have defined above.
Since there is a ``user`` relationship on the Token model, we can access this
``user`` with ``current_credential.user``.


MethodView & Flask-Restful
~~~~~~~~~~~~~~~~~~~~~~~~~~~

You can also use the ``require_oauth`` decorator in ``flask.views.MethodView``
and ``flask_restful.Resource``::

    from flask.views import MethodView

    class UserAPI(MethodView):
        decorators = [require_oauth()]


    from flask_restful import Resource

    class UserAPI(Resource):
        method_decorators = [require_oauth()]


Customize Signature Methods
---------------------------

The ``AuthorizationServer`` and ``ResourceProtector`` only support **HMAC-SHA1**
signature method by default. There are three signature methods built-in, which
can be enabled with the configuration::

    OAUTH1_SUPPORTED_SIGNATURE_METHODS = ['HMAC-SHA1', 'PLAINTEXT', 'RSA-SHA1']

It is also possible to extend the signature methods. For example, you want to
create a **HMAC-SHA256** signature method::

    import hmac
    from authlib.common.encoding import to_bytes
    from authlib.specs.rfc5849 import signature

    def verify_hmac_sha256(request):
        text = signature.generate_signature_base_string(request)

        key = escape(request.client_secret or '')
        key += '&'
        key += escape(request.token_secret or '')

        sig = hmac.new(to_bytes(key), to_bytes(text), hashlib.sha256)
        return binascii.b2a_base64(sig.digest())[:-1]

    AuthorizationServer.register_signature_method(
        'HMAC-SHA256', verify_hmac_sha256
    )
    ResourceProtector.register_signature_method(
        'HMAC-SHA256', verify_hmac_sha256
    )

Then add this method into **SUPPORTED_SIGNATURE_METHODS**::

    OAUTH1_SUPPORTED_SIGNATURE_METHODS = ['HMAC-SHA256']

With this configuration, your server will support **HMAC-SHA256** signature
method only. If you want to support more methods, add them to the list.
