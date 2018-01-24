Changelog
=========

.. meta::
   :description: The full list of changes between each Authlib release.

Here you can see the full list of changes between each Authlib release.

Version 0.4
-----------

**Release Date not Decided**

This is a feature releasing for OAuth 1 server, with several bug fixes.

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
- Mixin of SQLAlchemy models for easy integration.

.. admonition:: Breaking Changes

    The directory structure has been changed. Import Flask and Django client with
    the new modules::

        from authlib.flask.client import OAuth, RemoteApp
        from authlib.django.client import OAuth, RemoteApp

    Don't worry, they are backward compatible. You will be notified by warning
    messages.

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
