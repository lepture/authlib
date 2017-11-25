Changelog
=========

Here you can see the full list of changes between each Authlib release.


Version 0.2: Akemi
------------------

**Released on Nov 25, 2017**

This is a Beta version for Clients. You would expect that the clients works
well enough for daily use.

- :class:`~authlib.client.OAuthClient` is refactored to be the base class for
  Flask and Django.
- Add Django integrations :class:`authlib.client.django.OAuth` and
  :class:`authlib.client.django.RemoteApp`.
- Refactor on :class:`authlib.client.flask.OAuth` and
  :class:`authlib.client.flask.RemoteApp`.
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
- (beta) :class:`authlib.client.flask.OAuth`
