Changelog
=========

Here you can see the full list of changes between each Authlib release.


Version 0.2
-----------

**Release date not decided**

This is a Beta version for Clients. You would expect that the clients works
well enough for daily use.

- :class:`~authlib.client.OAuthClient` is refactored to be the base class for
  Flask and Django.


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
