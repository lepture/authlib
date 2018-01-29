.. _flask_oauth1_server:

Flask OAuth 1 Server
====================

.. meta::
   :description: How to create an OAuth 1 server in Flask with Authlib.
       And understand how OAuth 1 works.

Implement OAuth 1 provider in Flask. An OAuth 1 provider contains two servers:

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
save them into cache instead of database.

The cache implementation will be enabled by default if you have set a Flask
configuration::

    OAUTH1_AUTH_CACHE_TYPE = '{{ cache_type }}'

This is a ``OAUTH1_AUTH`` prefixed configuration for cache, find more
configuration at :ref:`flask_cache`.

If cache is not available, there is also a SQLAlchemy mixin::

    from authlib.flask.oauth1.sqla import OAuth1TemporaryCredentialMixin

    class TemporaryCredential(OAuth1TemporaryCredentialMixin):
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

    class TokenCredential(OAuth1TokenCredentialMixin):
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(
            db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
        )
        user = db.relationship('User')

    def set_grant_user(self, grant_user):
         # it is required to implement this method
        self.user_id = grant_user

If SQLAlchemy is not what you want, read the API reference of
:class:`~authlib.specs.rfc5849.TokenCredentialMixin` and implement the missing
methods.

Timestamp and Nonce
~~~~~~~~~~~~~~~~~~~

Server Implementation
~~~~~~~~~~~~~~~~~~~~~

Protect Resources
-----------------

Protect users resources, so that only the authorized clients with the
authorized access token can access the given scope resources.

A resource server can be a different server other than the authorization
server. Here is the way to protect your users' resources::

    from flask import jsonify
    from authlib.flask.oauth1 import ResourceProtector, current_credential

    def query_token(client_id, token):
        return TokenCredential.query.filter_by(
            client_id=client_id, oauth_token=token
        ).first()

    require_oauth = ResourceProtector(Client, query_token)

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
