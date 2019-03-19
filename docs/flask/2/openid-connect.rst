.. _flask_odic_server:

Flask OpenID Connect 1.0
========================

.. meta::
    :description: How to create an OpenID Connect server in Flask with Authlib.
        And understand how OpenID Connect works.

OpenID Connect 1.0 is supported from version 0.6. The integrations are built
with :ref:`flask_oauth2_custom_grant_types`. Since OpenID Connect is built on
OAuth 2.0 frameworks, you need to read :ref:`flask_oauth2_server` at first.

.. module:: authlib.oauth2.rfc6749.grants

Configuration
-------------

OpenID Connect 1.0 requires JWT. It can be enabled by setting::

    OAUTH2_JWT_ENABLED = True

When JWT is enabled, these configurations are available:

==================== =================================
OAUTH2_JWT_ALG       Algorithm for JWT
OAUTH2_JWT_KEY       Private key (in text) for JWT
OAUTH2_JWT_KEY_PATH  Private key path for JWT
OAUTH2_JWT_ISS       Issuer value for JWT
OAUTH2_JWT_EXP       JWT expires time, default is 3600
==================== =================================

OAUTH2_JWT_ALG
~~~~~~~~~~~~~~

The algorithm to sign a JWT. This is the ``alg`` value defined in header
part of a JWS:

.. code-block:: json

    {"alg": "RS256"}

The available algorithms are defined in :ref:`specs/rfc7518`, which are:

- HS256: HMAC using SHA-256
- HS384: HMAC using SHA-384
- HS512: HMAC using SHA-512
- RS256: RSASSA-PKCS1-v1_5 using SHA-256
- RS384: RSASSA-PKCS1-v1_5 using SHA-384
- RS512: RSASSA-PKCS1-v1_5 using SHA-512
- ES256: ECDSA using P-256 and SHA-256
- ES384: ECDSA using P-384 and SHA-384
- ES512: ECDSA using P-521 and SHA-512
- PS256: RSASSA-PSS using SHA-256 and MGF1 with SHA-256
- PS384: RSASSA-PSS using SHA-384 and MGF1 with SHA-384
- PS512: RSASSA-PSS using SHA-512 and MGF1 with SHA-512

The HMAC using SHA algorithms are not suggested since you need to share
secrets between server and client. Most OpenID Connect services are using
``RS256``.

OAUTH2_JWT_KEY / OAUTH2_JWT_KEY_PATH
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A private key is required to generate JWT. The value can be configured with
either ``OAUTH2_JWT_KEY`` or ``OAUTH2_JWT_KEY_PATH``. The key that you are
going to use dependents on the ``alg`` you are using. For instance, the alg
is ``RS256``, you need to use a RSA private key. It can be set with::

    OAUTH2_JWT_KEY = '''-----BEGIN RSA PRIVATE KEY-----\nMIIEog...'''

    # or in JWK format
    OAUTH2_JWT_KEY = {"kty": "RSA", "n": ...}

    # or in JWK set format
    OAUTH2_JWT_KEY = {"keys": [{"kty": "RSA", "kid": "uu-id", ...}, ...]}

If you are using JWK set format, that would be better. Authlib will randomly
choose a key among them to sign the JWT. To make it easier for maintenance,
``OAUTH2_JWT_KEY_PATH`` is a good choice::

    OAUTH2_JWT_KEY_PATH = '/path/to/rsa_private.pem'
    OAUTH2_JWT_KEY_PATH = '/path/to/jwk_set_private.json'

OAUTH2_JWT_ISS
~~~~~~~~~~~~~~

The ``iss`` value in JWT payload. The value can be your website name or URL.
For example, Google is using::

    {"iss": "https://accounts.google.com"}

.. _flask_odic_code:

Code Flow
---------

OpenID Connect Code flow looks like the standard Authorization Code flow, and
the implementation for :class:`OpenIDCodeGrant` is actually a subclass of
:ref:`flask_oauth2_code_grant`. And the implementation is the same::

    from authlib.oidc.core import grants
    from authlib.common.security import generate_token

    class OpenIDCodeGrant(grants.OpenIDCodeGrant):
        def create_authorization_code(self, client, grant_user, request):
            # you can use other method to generate this code
            code = generate_token(48)
            # openid request MAY have "nonce" parameter
            nonce = request.data.get('nonce')
            item = AuthorizationCode(
                code=code,
                client_id=client.client_id,
                redirect_uri=request.redirect_uri,
                scope=request.scope,
                nonce=nonce,
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
    server.register_grant(OpenIDCodeGrant)

The difference between OpenID Code flow and the standard code flow is that
OpenID Connect request has a scope of "openid":

.. code-block:: http

    GET /authorize?
    response_type=code
    &scope=openid%20profile%20email
    &client_id=s6BhdRkqt3
    &state=af0ifjsldkj
    &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb HTTP/1.1
    Host: server.example.com

:class:`OpenIDCodeGrant` can handle the standard code flow too. You **MUST NOT**
use them together.

.. important::

    If the server can handle OpenID requests, use :class:`OpenIDCodeGrant`.
    DON'T ``register_grant(AuthorizationCodeGrant)``.

.. _flask_odic_implicit:

Implicit Flow
-------------

Implicit flow is simple, there is no missing methods should be implemented,
we can simply import it and register it::

    from authlib.oidc.core import grants
    server.register_grant(grants.OpenIDImplicitGrant)

.. _flask_odic_hybrid:

Hybrid Flow
------------

Hybrid flow is a mix of the code flow and implicit flow. The missing methods
are the same with code flow::

    from authlib.oidc.core import grants
    from authlib.common.security import generate_token

    class OpenIDHybridGrant(grants.OpenIDHybridGrant):
        def create_authorization_code(self, client, grant_user, request):
            # you can use other method to generate this code
            code = generate_token(48)
            # openid request MAY have "nonce" parameter
            nonce = request.data.get('nonce')
            item = AuthorizationCode(
                code=code,
                client_id=client.client_id,
                redirect_uri=request.redirect_uri,
                scope=request.scope,
                nonce=nonce,
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
    server.register_grant(OpenIDHybridGrant)
