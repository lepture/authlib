Changelog
=========

Here you can see the full list of changes between each Authlib release.


Version 0.3: Nagato
-------------------

**Release Date not Decided**

This is a feature releasing for OAuth 2 server. Since this is the first
release of the server implementation, you would expect that there are bugs,
security vulnerabilities, and uncertainties. Try it bravely.

- RFC6749, all grant types, refresh token, authorization server.
- RFC6750, bearer token creation and validation.
- RFC7009, token revocation.
- Flask implementation of authorization server and resource protector.
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
