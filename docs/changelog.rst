Changelog
=========

.. meta::
   :description: The full list of changes between each Authlib release.

Here you can see the full list of changes between each Authlib release.


Version 0.5
-----------

**Release Date not Decided**

- Added :meth:`~authlib.specs.rfc6749.register_error_uri` and its Flask
  integration.
- :class:`~authlib.client.OAuth2Session` supports more grant types.
- Deprecate built-in cache. Read more on `issue#23`_.
- **Redesigned OAuth 1 Flask server**. Read the docs :ref:`flask_oauth1_server`.
- Deprecate ``client_model``. Read more on `issue#27`_.

.. _`issue#23`: https://github.com/lepture/authlib/issues/23
.. _`issue#27`: https://github.com/lepture/authlib/issues/27

.. admonition:: Rollback

    Rollback the breaking change in Version 0.4. Pass ``grant_user`` as a
    user instance::

        @app.route('/authorize', methods=['POST'])
        def confirm_authorize():
            if request.form['confirm'] == 'ok':
                # HERE
                grant_user = current_user
            else:
                grant_user = None
            return server.create_authorization_response(grant_user)

    Read the documentation on :ref:`flask_oauth2_server`, and search for
    ``grant_user``.

.. admonition:: Breaking Changes

    Update the initialization for AuthorizationServer and ResourceProtector
    for both OAuth 1 and OAuth 2::

        from authlib.flask.oauth2 import AuthorizationServer
        from your_project.models import Client

        server = AuthorizationServer(app, client_model=Client)
        # or lazily
        server = AuthorizationServer()
        server.init_app(app, client_model=Client)


        from authlib.flask.oauth1 import AuthorizationServer, ResourceProtector

        server = AuthorizationServer(app, client_model=Client)
        # or lazily
        server.init_app(app, client_model=Client)

        require_oauth = ResourceProtector(
            app, client_model=Client,
            query_token=query_token,
            exists_nonce=exists_nonce,
        )
        # or initialize it lazily
        require_oauth = ResourceProtector()
        require_oauth.init_app(
            app, client_model=Client,
            query_token=query_token,
            exists_nonce=exists_nonce,
        )

Version 0.4.1
-------------

**Released on Feb 2, 2018. A Quick Bugfix**

- Fixed missing code params when fetching access token. This bug is
  introduced when fixing `issue#16`_.

Version 0.4: Tsukino
--------------------

**Released on Jan 31, 2018. Enjoy the Super Blue Blood Moon!**

This is a feature releasing for OAuth 1 server. Things are not settled yet,
there will still be breaking changes in the future. Some of the breaking
changes are compatible with deprecated messages, a few are not. I'll keep the
deprecated message for 2 versions. Here is the main features:

- :ref:`RFC5847 <specs/rfc5849>`, OAuth 1 client and server
- :ref:`Flask implementation <flask_oauth1_server>` of OAuth 1 authorization
  server and resource protector.
- Mixin of SQLAlchemy models for easy integration with OAuth 1.

In version 0.4, there is also several bug fixes. Thanks for the early
contributors.

- Allow Flask OAuth register ``fetch_token`` and ``update_token``.
- Bug fix for OAuthClient when ``refresh_token_params`` is None via `PR#14`_.
- Don't pass everything in request args for Flask OAuth client via `issue#16`_.
- Bug fix for ``IDToken.validate_exp`` via `issue#17`_.

.. _`PR#14`: https://github.com/lepture/authlib/pull/14
.. _`issue#16`: https://github.com/lepture/authlib/issues/16
.. _`issue#17`: https://github.com/lepture/authlib/issues/17

.. admonition:: Breaking Changes

    For OAuth 2 server, it is suggested that you pass the user ID instead of user
    object to ``create_authorization_response``::

        @app.route('/authorize', methods=['POST'])
        def confirm_authorize():
            if request.form['confirm'] == 'ok':
                # pass ID instead of current_user object
                grant_user = current_user.id
            else:
                grant_user = None
            return server.create_authorization_response(grant_user)

    It will make things simple with an int/string value instead of an object. In
    the meantime, the implementation of ``AuthorizationCodeGrant`` and
    ``ImplicitGrant`` should be changed too. Read the documentation on :ref:`flask_oauth2_server`.

.. admonition:: Deprecated Changes

    There are parameters naming changes in the client part:

    * ``client_key`` has been changed to ``client_id``
    * ``resource_owner_key`` has been changed to ``token``
    * ``resource_owner_secret`` has been changed to ``token_secret``

    There is a huge change in client apps. Instead of ``fetch_user``, it is
    suggested that you use ``profile()`` instead, which will return a UserInfo
    object.

    Currently, they are backward compatible. You will be notified by warnings.

Version 0.3: Nagato
-------------------

**Released on Dec 24, 2017. Merry Christmas!**

This is a feature releasing for OAuth 2 server. Since this is the first
release of the server implementation, you would expect that there are bugs,
security vulnerabilities, and uncertainties. Try it bravely.

- :ref:`RFC6749 <specs/rfc6749>`, all grant types, refresh token, authorization server.
- :ref:`RFC6750 <specs/rfc6750>`, bearer token creation and validation.
- :ref:`RFC7009 <specs/rfc7009>`, token revocation.
- :ref:`Flask implementation <flask_oauth2_server>` of authorization server and resource protector.
- Mixin of SQLAlchemy models for easy integration with OAuth 2.

Version 0.2.1
-------------

**Released on Dec 6, 2017**

This is a bugfix version for Akemi. Sorry for the typo.

- Fixed a typo in :meth:`~authlib.client.OAuth2Session.fetch_access_token`
  which caused `issue #5`_.
- Removed pyjwt dependency from rfc5849.

.. _`issue #5`: https://github.com/lepture/authlib/issues/5

Version 0.2: Akemi
------------------

**Released on Nov 25, 2017**

This is a Beta version for Clients. You would expect that the clients works
well enough for daily use.

- :class:`~authlib.client.OAuthClient` is refactored to be the base class for
  Flask and Django.
- Add Django integrations :class:`authlib.django.client.OAuth` and
  :class:`authlib.django.client.RemoteApp`.
- Refactor on :class:`authlib.flask.client.OAuth` and
  :class:`authlib.flask.client.RemoteApp`.
- Refactor on :ref:`client_apps`, make it stable and ready to use.

Version 0.1
-----------

**Released on Nov 18, 2017.**

This is an Alpha version for previewing. You can expect there are many
features missing, however the client part works well enough. These APIs are
considered stable enough to use in production:

- (stable) :class:`~authlib.client.OAuth1Session`
- (stable) :class:`~authlib.client.OAuth2Session`
- (beta) :class:`~authlib.client.OAuthClient`
- (beta) :class:`authlib.flask.client.OAuth`
