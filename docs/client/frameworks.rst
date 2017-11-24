.. _client_frameworks:

Integrated Frameworks
=====================

Authlib has built-in integrated frameworks support, which makes
it much easier to develop with your favorite framework.

.. _flask_client:

Flask
-----

.. module:: authlib.client.flask

Flask OAuth client can handle OAuth 1 and OAuth 2 services.
It shares a similar API with Flask-OAuthlib, you can
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

Cache & Database
~~~~~~~~~~~~~~~~

The remote app that :meth:`OAuth.register` configured, is a subclass of
:class:`~authlib.client.OAuthClient`. You can read more on :ref:`oauth_client`.
There are hooks for OAuthClient, and flask integration has registered them
all for you. However, you need to configure cache and database access.

Cache is used for temporary information, such as request token, state and
callback uri. We use the :class:`~authlib.common.flask.cache.Cache` as the
backend. To specify a certain cache type, config with::

    OAUTH_CLIENT_CACHE_TYPE = '{{ cache_type }}'

Find more configuration on :ref:`flask_cache`. Please note, the
``config_prefix`` is::

    OAUTH_CLIENT

For database, we need a class which has two class methods. It would be
something like::

    class MyTokenModel(db.Model):
        OAUTH1_TOKEN_TYPE = 'oauth1.0'

        user_id = Column(Integer, nullable=False)
        name = Column(String(20), nullable=False)

        token_type = Column(String(20))
        access_token = Column(String(48), nullable=False)
        # refresh_token or access_token_secret
        alt_token = Column(String(48))
        expires_at = Column(Integer, default=0)

        @classmethod
        def fetch_token(cls, name):
            q = cls.query.filter_by(name=name, user_id=current_user.id)
            item = q.first()
            if item.token_type == cls.OAUTH1_TOKEN_TYPE:
                return dict(
                    oauth_token=self.access_token,
                    oauth_token_secret=self.alt_token,
                )
            return dict(
                access_token=self.access_token,
                token_type=self.token_type,
                refresh_token=self.refresh_token,
                expires_at=self.expires_at,
            )

        @classmethod
        def update_token(cls, name, token):
            item = cls(name=name, user_id=current_user.id)
            if 'oauth_token' in token:
                item.token_type = cls.OAUTH1_TOKEN_TYPE
                item.access_token = token['oauth_token']
                item.alt_token = token['oauth_token_secret']
            else:
                item.token_type = token.get('token_type', 'bearer')
                item.access_token = token.get('access_token')
                item.alt_token = token.get('refresh_token')
                item.expires_at = token.get('expires_at')
            db.session.add(item)
            db.session.commit()
            return item

You need to register this **TokenModel** in the registry::

    oauth = OAuth(app, token_model=MyTokenModel)

Implement the Server
~~~~~~~~~~~~~~~~~~~~

Now it's time to make everything works. We need routes for log in and
authorization::

    from flask import Blueprint

    bp = Blueprint(__name__, 'auth')

    @bp.route('/login')
    def login():
        callback_uri = url_for('.authorize', _external=True)
        return oauth.twitter.authorize_redirect(callback_uri)

    @bp.route('/authorize')
    def authorize():
        token = oauth.twitter.authorize_access_token()
        # this is a pseudo method, you need to implement it yourself
        MyTokenModel.save(token)
        return redirect('/profile')

The only methods you need to call are :meth:`~RemoteApp.authorize_redirect`
and :meth:`~RemoteApp.authorize_access_token`. When you have obtained access
token, make requests with your remote app::

    >>> resp = oauth.twitter.get('account/verify_credentials.json')
    >>> print(resp.json())

Django
------

.. module:: authlib.client.django

The Django client shares a similar API with Flask client. But there are
differences, since Django has no request context, you need to pass ``request``
argument yourself.

Create a registry with :class:`OAuth` object::

    from authlib.client.django import OAuth

    oauth = OAuth()

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
pair can be omit. They can be configured from your Django settings::

    AUTHLIB_OAUTH_CLIENTS = {
        'twitter': {
            'client_key': 'Twitter Consumer Key',
            'client_secret': 'Twitter Consumer Secret',
            'request_token_url': 'https://api.twitter.com/oauth/request_token',
            'request_token_params': None,
            'access_token_url': 'https://api.twitter.com/oauth/access_token',
            'access_token_params': None,
            'refresh_token_url': None,
            'authorize_url': 'https://api.twitter.com/oauth/authenticate',
            'api_base_url': 'https://api.twitter.com/1.1/',
            'client_kwargs': None
        }
    }

Sessions Middleware
~~~~~~~~~~~~~~~~~~~

In OAuth 1, Django client will save the request token in sessions. In this
case, you need to configure Session Middleware in Django::

    MIDDLEWARE = [
        'django.contrib.sessions.middleware.SessionMiddleware'
    ]

Follow the official Django documentation to set a proper session. Either a
database backend or a cache backend would work well.

.. warning::

    Be aware, using secure cookie as session backed will expose your request
    token.


Database Design
~~~~~~~~~~~~~~~

Authlib Django client has no built-in database model. You need to design the
Token model by yourself. This is designed by intention.

Here are some hints on how to design your schema:

1. in OAuth 1, token is structured as ``oauth_token`` and ``oauth_token_secret``.
2. in OAuth 2, token is structured as ``access_token``, ``refresh_token`` and
   ``expires_in``.

To use a single model for OAuth 1 and OAuth 2, you can create::

    class OAuthToken(models.Model):
        # twitter, github, facebook, etc.
        name = models.CharField(max_length=40)
        # oauth1, bearer, mac, etc.
        token_type = models.CharField(max_length=20)
        # oauth_token in OAuth 1, or access_token in OAuth 2
        token = models.CharField(max_length=200)
        # oauth_token_secret in OAuth 1, or refresh_token in OAuth 2
        alt_token = models.CharField(max_length=200)
        # oauth 2 expires time
        expires_at = models.DateTimeField()
        # ...

.. note::

    In the future, we will provide a full featured Django App in another
    library.

Implement the Server
~~~~~~~~~~~~~~~~~~~~

There are two views to be completed, no matter it is OAuth 1 or OAuth 2::

    def login(request):
        # build a full authorize callback uri
        callback_uri = request.build_absolute_uri('/authorize')
        return oauth.twitter.authorize_redirect(request, callback_uri)

    def authorize(request):
        token = oauth.twitter.authorize_access_token(request)
        # save_token_to_db(token)
        return '...'

    def fetch_resource(request):
        token = get_user_token_from_db(request.user)
        # remember to assign user's token to the client
        oauth.twitter.token = token
        resp = oauth.twitter.get('account/verify_credentials.json')
        profile = resp.json()
        # ...


Compliance Fix
--------------

The :class:`RemoteApp` is a subclass of :class:`~authlib.client.OAuthClient`,
they share the same logic for compliance fix. Construct a method to fix
requests session as in :ref:`compliance_fix_mixed`::

    def compliance_fix(session):

        def fix_protected_request(url, headers, data):
            # do something
            return url, headers, data

        session.register_compliance_hook(
            'protected_request', fix_protected_request)

When :meth:`OAuth.register` a remote app, pass it in the parameters::

    oauth.register('twitter', {
        'client_key': '...',
        'client_secret': '...',
        ...,
        'compliance_fix': compliance_fix,
        ...
    })
