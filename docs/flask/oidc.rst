.. _flask_odic_server:

Flask OpenID Connect Server
===========================

.. meta::
    :description: How to create an OpenID Connect server in Flask with Authlib.
        And understand how OpenID Connect works.

OpenID Connect 1.0 is supported from version 0.6. The integration is built as
:ref:`flask_oauth2_custom_grant_types`.

.. module:: authlib.specs.rfc6749.grants

Code Flow
---------

OpenID Connect Code flow looks like the standard Authorization Code flow, and
the implementation for :class:`OpenIDCodeGrant` is actually a subclass of
:ref:`flask_oauth2_code_grant`. And the implementation is the same::

    from authlib.specs.oidc import grants
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
use use them together.

.. admonition:: Notice

    If the server can handle OpenID requests, use :class:`OpenIDCodeGrant`.
    DON'T ``register_grant(AuthorizationCodeGrant)``.

Implicit Flow
-------------

Implicit flow is simple, there is no missing methods should be implemented,
we can simply import it and register it::

    from authlib.specs.oidc import grants
    server.register_grant(grants.OpenIDImplicitGrant)

Hybrid Flow
------------

Hybrid flow is a mix of the code flow and implicit flow. The missing methods
are the same with code flow::

    from authlib.specs.oidc import grants
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
