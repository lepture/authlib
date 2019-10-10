.. _starlette_client:

Starlette OAuth Client
======================

.. meta::
    :description: The built-in Starlette integrations for OAuth 1.0, OAuth 2.0
        and OpenID Connect clients, powered by Authlib.

.. module:: authlib.integrations.starlette_client
    :noindex:

This documentation covers OAuth 1.0, OAuth 2.0 and OpenID Connect Client
support for Starlette. Because all the frameworks integrations share the
same API, it is best to read :ref:`frameworks_clients` at first.

The difference between Starlette and Flask/Django integrations is Starlette
is **async**. We will use ``await`` for the functions we need to call. But
first, let's create an :class:`OAuth` instance::

    from authlib.integrations.starlette_client import OAuth

    oauth = OAuth()

The common use case for OAuth is authentication, e.g. let your users log in
with Twitter, GitHub, Google etc.

Register Remote Apps
--------------------

``oauth.register`` is the same as :ref:`frameworks_clients`, please read
that documentation at first.

However, unlike Flask/Django, Starlette OAuth registry is using HTTPX
:class:`~authlib.integrations.httpx_client.AsyncOAuth1Client` and
:class:`~authlib.integrations.httpx_client.AsyncOAuth2Client` as the client
backends. While Flask and Django are using the Requests version of
:class:`~authlib.integrations.requests_client.OAuth1Session` and
:class:`~authlib.integrations.requests_client.OAuth2Session`.


Configuration
-------------

Starlette can load configuration from environment; Authlib implementation
for Starlette client can use this configuration. Here is an example of how
to do it::

    from starlette.config import Config

    config = Config('.env')
    oauth = OAuth(config)

Authlib will load ``client_id`` and ``client_secret`` from the configuration,
take google as an example::

    oauth.register(name='google', ...)

It will load **GOOGLE_CLIENT_ID** and **GOOGLE_CLIENT_SECRET** from the
environment.


Using Cache for Temporary Credential
------------------------------------

With OAuth 1.0, we need to use a temporary credential to exchange for an access token.
This temporary credential is created before redirecting to the provider (Twitter),
and needs to be saved somewhere in order to use it later.

With OAuth 1, the Starlette client will save the request token in sessions. To
enable this, we need to add the ``SessionMiddleware`` middleware to the
application, which requires the installation of the ``itsdangerous`` package::

    from starlette.applications import Starlette
    from starlette.middleware.sessions import SessionMiddleware

    app = Starlette()
    app.add_middleware(SessionMiddleware, secret_key="some-random-string")

However, using the ``SessionMiddleware`` will store the temporary credential as
a secure cookie which will expose your request token to the client. If you want
to improve security on this part, it is possible by passing a cache instance::

    oauth = OAuth(cache=cache)

In this way, Authlib will save the ``request_token`` into your cache. The ``cache``
instance MUST have methods:

- ``.get(key)``
- ``.set(key, value, expires=None)``
