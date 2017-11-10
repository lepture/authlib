.. _client-frameworks:

Integrated Frameworks
=====================

Authlib has built-in integrated frameworks support, which makes
it much easier to develop with your favorite framework.

Flask
-----

.. module:: authlib.client.flask

Flask OAuth client is completed, it can handle OAuth 1 and OAuth 2
services. It shares a similar API with Flask-OAuthlib, you can
transfer your code from Flask-OAuthlib to Authlib with ease.

Create a registry with :class:`OAuth` object::

    from authlib.client.flask import OAuth

    oauth = OAuth(app)

You can initialize it later with :meth:`~OAuth.init_app` method::

    oauth = OAuth()
    oauth.init_app(app)

Configuration
~~~~~~~~~~~~~

To register a remote application on OAuth registry, using the
:meth:`~OAuth.register` method::

    oauth.register('twitter', {
        'client_key': 'Twitter Consumer Key',
        'client_secret': 'Twitter Consumer Secret',
        'request_token_url': 'https://api.twitter.com/oauth/request_token',
        'request_token_params': None,
        'access_token_url': 'https://api.twitter.com/oauth/access_token',
        'access_token_params': None,
        'refresh_token_url': None,
        'authorize_url': 'https://api.twitter.com/oauth/authenticate',
        'api_base_url': 'https://api.twitter.com/1.1/',
        'client_kwargs': None,
    })

The first parameter in ``register`` method is the **name** of the remote
application. You can access the remote application with::

    oauth.twitter.get('account/verify_credentials.json')

The second paramter in ``register`` method is configuration. Every key value
pair can be omit. They can be configured in your Flask App configuration.
Config key is formatted with ``{name}_{key}`` in uppercase, e.g.

========================== ================================
TWITTER_CLIENT_KEY         Twitter Consumer Key
TWITTER_CLIENT_SECRET      Twitter Consumer Secret
TWITTER_REQUEST_TOKEN_URL  URL to fetch OAuth request token
========================== ================================

If you register your remote app as ``oauth.register('example', {...})``, the
config key would look like:

========================== ===============================
EXAMPLE_CLIENT_KEY         Twitter Consumer Key
EXAMPLE_CLIENT_SECRET      Twitter Consumer Secret
EXAMPLE_ACCESS_TOKEN_URL   URL to fetch OAuth access token
========================== ===============================

Token Model
~~~~~~~~~~~

OAuth 1 & OAuth 2
~~~~~~~~~~~~~~~~~


Django
------

(Under Construction)


Compliance Fix
--------------
