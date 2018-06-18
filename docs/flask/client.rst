.. _flask_client:

Flask OAuth Client
==================

.. meta::
    :description: The built-in Flask integrations for OAuth 1.0 and
        OAuth 2.0 clients.


.. module:: authlib.flask.client

Looking for OAuth providers?

- :ref:`flask_oauth1_server`
- :ref:`flask_oauth2_server`

Flask OAuth client can handle OAuth 1 and OAuth 2 services. It shares a
similar API with Flask-OAuthlib, you can transfer your code from
Flask-OAuthlib to Authlib with ease. Here is how to
`Migrate OAuth Client from Flask-OAuthlib to Authlib
<https://blog.authlib.org/2018/migrate-flask-oauthlib-client-to-authlib>`_.

Create a registry with :class:`OAuth` object::

    from authlib.flask.client import OAuth

    oauth = OAuth(app)

You can initialize it later with :meth:`~OAuth.init_app` method::

    oauth = OAuth()
    oauth.init_app(app)

Configuration
-------------

To register a remote application on OAuth registry, using the
:meth:`~OAuth.register` method::

    oauth.register('twitter',
        client_id='Twitter Consumer Key',
        client_secret='Twitter Consumer Secret',
        request_token_url='https://api.twitter.com/oauth/request_token',
        request_token_params=None,
        access_token_url='https://api.twitter.com/oauth/access_token',
        access_token_params=None,
        refresh_token_url=None,
        authorize_url='https://api.twitter.com/oauth/authenticate',
        api_base_url='https://api.twitter.com/1.1/',
        client_kwargs=None,
    )

The first parameter in ``register`` method is the **name** of the remote
application. You can access the remote application with::

    oauth.twitter.get('account/verify_credentials.json')

The second parameter in ``register`` method is configuration. Every key value
pair can be omit. They can be configured in your Flask App configuration.
Config key is formatted with ``{name}_{key}`` in uppercase, e.g.

========================== ================================
TWITTER_CLIENT_ID          Twitter Consumer Key
TWITTER_CLIENT_SECRET      Twitter Consumer Secret
TWITTER_REQUEST_TOKEN_URL  URL to fetch OAuth request token
========================== ================================

If you register your remote app as ``oauth.register('example', ...)``, the
config key would look like:

========================== ===============================
EXAMPLE_CLIENT_ID          Twitter Consumer Key
EXAMPLE_CLIENT_SECRET      Twitter Consumer Secret
EXAMPLE_ACCESS_TOKEN_URL   URL to fetch OAuth access token
========================== ===============================

The remote app that :meth:`OAuth.register` configured, is a subclass of
:class:`~authlib.client.OAuthClient`. You can read more on :ref:`oauth_client`.
There are hooks for OAuthClient, and flask integration has registered them
all for you.

Here is a full list of the configuration keys:

- ``{name}_CLIENT_ID``: Client key of OAuth 1, or Client ID of OAuth 2
- ``{name}_CLIENT_SECRET``: Client secret of OAuth 2, or Client Secret of OAuth 2
- ``{name}_REQUEST_TOKEN_URL``: Request Token endpoint for OAuth 1
- ``{name}_REQUEST_TOKEN_PARAMS``: Extra parameters for Request Token endpoint
- ``{name}_ACCESS_TOKEN_URL``: Access Token endpoint for OAuth 1 and OAuth 2
- ``{name}_ACCESS_TOKEN_PARAMS``: Extra parameters for Access Token endpoint
- ``{name}_REFRESH_TOKEN_URL``: Refresh Token endpoint for OAuth 2 (if any)
- ``{name}_REFRESH_TOKEN_PARAMS``: Extra parameters for Refresh Token endpoint
- ``{name}_AUTHORIZE_URL``: Endpoint for user authorization of OAuth 1 ro OAuth 2
- ``{name}_AUTHORIZE_PARAMS``: Extra parameters for Authorization Endpoint.
- ``{name}_API_BASE_URL``: A base URL endpoint to make requests simple
- ``{name}_CLIENT_KWARGS``: Extra keyword arguments for OAuth1Session or OAuth2Session

Database
--------

.. note:: If OAuth login is what you need ONLY, you don't need to configure
    a database with ``fetch_token`` method.

We need to ``fetch_token`` from database for later requests. Here is an
example on database schema design::

    class OAuth1Token(db.Model)
        user_id = Column(Integer, nullable=False)
        name = Column(String(20), nullable=False)

        oauth_token = Column(String(48), nullable=False)
        oauth_token_secret = Column(String(48))

        def to_token(self):
            return dict(
                oauth_token=self.access_token,
                oauth_token_secret=self.alt_token,
            )

    class OAuth2Token(db.Model):
        user_id = Column(Integer, nullable=False)
        name = Column(String(20), nullable=False)

        token_type = Column(String(20))
        access_token = Column(String(48), nullable=False)
        refresh_token = Column(String(48))
        expires_at = Column(Integer, default=0)

        def to_token(self):
            return dict(
                access_token=self.access_token,
                token_type=self.token_type,
                refresh_token=self.refresh_token,
                expires_at=self.expires_at,
            )

To send requests on behalf of the user, you need to save user's access token
into database after ``authorize_access_token``. Then use the access token
with ``fetch_token`` from database.

OAuth 1 Request Token
---------------------

OAuth 1 requires a temporary request token for exchanging access token. There
should be a place to store these temporary information. If a cache system is
available, the ONLY thing you need to do is pass the cache instance into OAuth
registry. A ``cache`` interface MUST have methods:

- ``.get(key)``
- ``.set(key, value, expires=None)``

Pass the ``cache`` instance into OAuth registry::

    from authlib.flask.client import OAuth

    oauth = OAuth(app)
    # or initialize lazily
    oauth = OAuth()
    oauth.init_app(app, cache=cache)

If cache system is not available, you can define methods for retrieving and
saving request token::

    def save_request_token(token):
        save_request_token_to_someplace(current_user, token)

    def fetch_request_token():
        return get_request_token_from_someplace(current_user)

    # register the two methods
    oauth.register('twitter',
        client_id='Twitter Consumer Key',
        client_secret='Twitter Consumer Secret',
        request_token_url='https://api.twitter.com/oauth/request_token',
        request_token_params=None,
        access_token_url='https://api.twitter.com/oauth/access_token',
        access_token_params=None,
        refresh_token_url=None,
        authorize_url='https://api.twitter.com/oauth/authenticate',
        api_base_url='https://api.twitter.com/1.1/',
        client_kwargs=None,
        # NOTICE HERE
        save_request_token=save_request_token,
        fetch_request_token=fetch_request_token,
    )

Implement the Server
--------------------

Let's take Twitter as an example, we need to define routes for login and
authorization::

    from flask import url_for, render_template

    @app.route('/login')
    def login():
        redirect_uri = url_for('authorize', _external=True)
        return oauth.twitter.authorize_redirect(redirect_uri)

    @app.route('/authorize')
    def authorize():
        token = oauth.twitter.authorize_access_token()
        # this is a pseudo method, you need to implement it yourself
        OAuth1Token.save(current_user, token)
        return redirect(url_for('twitter_profile'))

    @app.route('/profile')
    def twitter_profile():
        resp = oauth.twitter.get('account/verify_credentials.json')
        profile = resp.json()
        return render_template('profile.html', profile=profile)

There will be an issue with ``/profile`` since you our registry don't know
current user's Twitter access token. We need to design a ``fetch_token``,
and grant it to the registry::

    def fetch_twitter_token():
        item = OAuth1Token.query.filter_by(
            name='twitter', user_id=current_user.id
        ).first()
        return item.to_token()

    # we can registry this ``fetch_token`` with oauth.register
    oauth.register(
        'twitter',
        client_id='Twitter Consumer Key',
        client_secret='Twitter Consumer Secret',
        request_token_url='https://api.twitter.com/oauth/request_token',
        request_token_params=None,
        access_token_url='https://api.twitter.com/oauth/access_token',
        access_token_params=None,
        refresh_token_url=None,
        authorize_url='https://api.twitter.com/oauth/authenticate',
        api_base_url='https://api.twitter.com/1.1/',
        client_kwargs=None,
        # NOTICE HERE
        fetch_token=fetch_twitter_token,
    )

Since the OAuth registry can contain many services, it would be good enough
to share some common methods instead of defining them one by one. Here are
some hints::

    from flask import url_for, render_template

    @app.route('/login/<name>')
    def login(name):
        client = oauth.create_client(name)
        redirect_uri = url_for('authorize', name=name, _external=True)
        return client.authorize_redirect(redirect_uri)

    @app.route('/authorize/<name>')
    def authorize(name):
        client = oauth.create_client(name)
        token = client.authorize_access_token()
        if name in OAUTH1_SERVICES:
            # this is a pseudo method, you need to implement it yourself
            OAuth1Token.save(current_user, token)
        else:
            # this is a pseudo method, you need to implement it yourself
            OAuth2Token.save(current_user, token)
        return redirect(url_for('profile', name=name))

    @app.route('/profile/<name>')
    def profile(name):
        client = oauth.create_client(name)
        resp = oauth.twitter.get(get_profile_url(name))
        profile = resp.json()
        return render_template('profile.html', profile=profile)

We can share a ``fetch_token`` method at OAuth registry level when
initialization. Define a common ``fetch_token``::

    def fetch_token(name):
        if name in OAUTH1_SERVICES:
            item = OAuth1Token.query.filter_by(
                name=name, user_id=current_user.id
            ).first()
        else:
            item = OAuth2Token.query.filter_by(
                name=name, user_id=current_user.id
            ).first()
        if item:
            return item.to_token()

    # pass ``fetch_token``
    oauth = OAuth(app, fetch_token=fetch_token)

    # or init app later
    oauth = OAuth(fetch_token=fetch_token)
    oauth.init_app(app)

    # or init everything later
    oauth = OAuth()
    oauth.init_app(app, fetch_token=fetch_token)

With this common ``fetch_token`` in OAuth, you don't need to design the method
for each services one by one.

Auto Refresh Token
------------------

In OAuth 2, there is a concept of ``refresh_token``, Authlib can auto refresh
access token when it is expired. If the services you are using don't issue any
``refresh_token`` at all, you don't need to do anything.

Just like ``fetch_token``, we can define a ``update_token`` method for each
remote app or sharing it in OAuth registry::

    def update_token(name, token):
        item = OAuth2Token.query.filter_by(
            name=name, user_id=current_user.id
        ).first()
        if not item:
            item = OAuth2Token(name=name, user_id=current_user.id)
        item.token_type = token.get('token_type', 'bearer')
        item.access_token = token.get('access_token')
        item.refresh_token = token.get('refresh_token')
        item.expires_at = token.get('expires_at')
        db.session.add(item)
        db.session.commit()
        return item

    # pass ``update_token``
    oauth = OAuth(app, update_token=update_token)

    # or init app later
    oauth = OAuth(update_token=update_token)
    oauth.init_app(app)

    # or init everything later
    oauth = OAuth()
    oauth.init_app(app, update_token=update_token)


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

    oauth.register('twitter',
        client_id='...',
        client_secret='...',
        ...,
        compliance_fix=compliance_fix,
        ...
    )

