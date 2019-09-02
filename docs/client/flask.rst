.. _flask_client:

Flask OAuth Client
==================

.. meta::
    :description: The built-in Flask integrations for OAuth 1.0 and
        OAuth 2.0 clients.


.. module:: authlib.flask.client
    :noindex:

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

You can also initialize it later with :meth:`~OAuth.init_app` method::

    oauth = OAuth()
    oauth.init_app(app)

The common use case for OAuth is authentication, e.g. let your users log in
with Twitter, GitHub, Google etc.

Log In with OAuth 1.0
---------------------

For instance, Twitter is an OAuth 1.0 service, you want your users to log in
your website with Twitter.

The first step is register a remote application on the ``OAuth`` registry via
:meth:`~OAuth.register` method::

    oauth.register(
        name='twitter',
        client_id='{{ your-twitter-consumer-key }}',
        client_secret='{{ your-twitter-consumer-secret }}',
        request_token_url='https://api.twitter.com/oauth/request_token',
        request_token_params=None,
        access_token_url='https://api.twitter.com/oauth/access_token',
        access_token_params=None,
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
EXAMPLE_CLIENT_ID          OAuth Consumer Key
EXAMPLE_CLIENT_SECRET      OAuth Consumer Secret
EXAMPLE_ACCESS_TOKEN_URL   URL to fetch OAuth access token
========================== ===============================

Here is a full list of the configuration keys:

- ``{name}_CLIENT_ID``: Client key of OAuth 1, or Client ID of OAuth 2
- ``{name}_CLIENT_SECRET``: Client secret of OAuth 2, or Client Secret of OAuth 2
- ``{name}_REQUEST_TOKEN_URL``: Request Token endpoint for OAuth 1
- ``{name}_REQUEST_TOKEN_PARAMS``: Extra parameters for Request Token endpoint
- ``{name}_ACCESS_TOKEN_URL``: Access Token endpoint for OAuth 1 and OAuth 2
- ``{name}_ACCESS_TOKEN_PARAMS``: Extra parameters for Access Token endpoint
- ``{name}_AUTHORIZE_URL``: Endpoint for user authorization of OAuth 1 ro OAuth 2
- ``{name}_AUTHORIZE_PARAMS``: Extra parameters for Authorization Endpoint.
- ``{name}_API_BASE_URL``: A base URL endpoint to make requests simple
- ``{name}_CLIENT_KWARGS``: Extra keyword arguments for OAuth1Session or OAuth2Session


The ``{name}_CLIENT_KWARGS`` is a dict configuration to pass extra parameters to
``OAuth1Session``. If you are using ``RSA-SHA1`` signature method::

    EXAMPLE_CLIENT_KWARGS = {
        'signature_method': 'RSA-SHA1',
        'signature_type': 'HEADER',
        'rsa_key': 'Your-RSA-Key'
    }

Saving Temporary Credential
~~~~~~~~~~~~~~~~~~~~~~~~~~~

In OAuth 1.0, we need to use a temporary credential to exchange access token,
this temporary credential was created before redirecting to the provider (Twitter),
we need to save this temporary credential somewhere in order to use it later.

Our ``OAuth`` registry provided a simple way to store temporary credentials, when
initializing ``OAuth``, you can pass an ``cache`` instance::

    oauth = OAuth(app, cache=cache)

    # or initialize lazily
    oauth = OAuth()
    oauth.init_app(app, cache=cache)

A ``cache`` instance MUST have methods:

- ``.get(key)``
- ``.set(key, value, expires=None)``


If cache system is not available, you can define methods for retrieving and
saving request token:

.. code-block:: python

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


Routes for Authorization
~~~~~~~~~~~~~~~~~~~~~~~~

After configuration of ``OAuth`` registry and the remote application, the
rest steps are much simpler. The only required parts are routes:

1. redirect to 3rd party provider (Twitter) for authentication
2. redirect back to your website to fetch access token and profile

Here is the example for Twitter login::

    from flask import url_for, render_template

    @app.route('/login')
    def login():
        redirect_uri = url_for('authorize', _external=True)
        return oauth.twitter.authorize_redirect(redirect_uri)

    @app.route('/authorize')
    def authorize():
        token = oauth.twitter.authorize_access_token()
        resp = oauth.twitter.get('account/verify_credentials.json')
        profile = resp.json()
        # do something with the token and profile
        return redirect('/')

After user confirmed on Twitter authorization page, it will redirect
back to your website ``/authorize``. In this route, you can get your
user's twitter profile information, you can store the user information
in your database, mark your user as logged in and etc.

Using OAuth 2.0 to Log In
-------------------------

For instance, GitHub is an OAuth 2.0 service, you want your users to log in
your website with GitHub.

The first step is register a remote application on the ``OAuth`` registry via
:meth:`~OAuth.register` method::

    oauth.register(
        name='github',
        client_id='{{ your-github-client-id }}',
        client_secret='{{ your-github-client-secret }}',
        access_token_url='https://github.com/login/oauth/access_token',
        authorize_url='https://github.com/login/oauth/authorize',
        api_base_url='https://api.github.com/',
        client_kwargs={'scope': 'user:email'},
    )

The first parameter in ``register`` method is the **name** of the remote
application. You can access the remote application with::

    oauth.github.get('user')

The second parameter in ``register`` method is configuration. Every key value
pair can be omit. They can be configured in your Flask App configuration.
Config key is formatted with ``{name}_{key}`` in uppercase, e.g.

========================== ================================
GITHUB_CLIENT_ID           GitHub Client ID
GITHUB_CLIENT_SECRET       GitHub Client Secret
========================== ================================

If you register your remote app as ``oauth.register('example', ...)``, the
config key would look like:

========================== ===============================
EXAMPLE_CLIENT_ID          OAuth 2 Client ID
EXAMPLE_CLIENT_SECRET      OAuth 2 Client Secret
========================== ===============================

Here is a full list of the configuration keys:

- ``{name}_CLIENT_ID``: Client key of OAuth 1, or Client ID of OAuth 2
- ``{name}_CLIENT_SECRET``: Client secret of OAuth 2, or Client Secret of OAuth 2
- ``{name}_ACCESS_TOKEN_URL``: Access Token endpoint for OAuth 1 and OAuth 2
- ``{name}_ACCESS_TOKEN_PARAMS``: Extra parameters for Access Token endpoint
- ``{name}_REFRESH_TOKEN_URL``: Refresh Token endpoint for OAuth 2 (if any)
- ``{name}_REFRESH_TOKEN_PARAMS``: Extra parameters for Refresh Token endpoint
- ``{name}_AUTHORIZE_URL``: Endpoint for user authorization of OAuth 1 ro OAuth 2
- ``{name}_AUTHORIZE_PARAMS``: Extra parameters for Authorization Endpoint.
- ``{name}_API_BASE_URL``: A base URL endpoint to make requests simple
- ``{name}_CLIENT_KWARGS``: Extra keyword arguments for OAuth1Session or OAuth2Session

The ``{name}_CLIENT_KWARGS`` is a dict configuration to pass extra parameters to
``OAuth2Session``, you can pass extra parameters like::

    EXAMPLE_CLIENT_KWARGS = {
        'scope': 'profile',
        'token_endpoint_auth_method': 'client_secret_basic',
        'token_placement': 'header',
    }

There are several ``token_endpoint_auth_method``, get a deep inside the
:ref:`client_auth_methods`.

Routes for Authorization
~~~~~~~~~~~~~~~~~~~~~~~~

After configuration of ``OAuth`` registry and the remote application, the
rest steps are much simpler. The only required parts are routes:

1. redirect to 3rd party provider (GitHub) for authentication
2. redirect back to your website to fetch access token and profile

Here is the example for GitHub login::

    from flask import url_for, render_template

    @app.route('/login')
    def login():
        redirect_uri = url_for('authorize', _external=True)
        return oauth.github.authorize_redirect(redirect_uri)

    @app.route('/authorize')
    def authorize():
        token = oauth.github.authorize_access_token()
        resp = oauth.github.get('user')
        profile = resp.json()
        # do something with the token and profile
        return redirect('/')

After user confirmed on GitHub authorization page, it will redirect
back to your website ``/authorize``. In this route, you can get your
user's GitHub profile information, you can store the user information
in your database, mark your user as logged in and etc.

Accessing OAuth Resources
-------------------------

There are also chances that you need to access your user's 3rd party
OAuth provider resources. For instance, you want to display your user's
GitHub profile::

    @app.route('/github/<username>')
    def github_profile(username):
        user = User.get_by_username(username)
        token = OAuth2Token.get(user_id=user.id, name='github')
        # API URL: https://api.github.com/user
        resp = oauth.github.get('user', token=token.to_token())
        profile = resp.json()
        return render_template('github.html', profile=profile)

In this case, we need a place to store the access token in order to use
it later. Take an example, we want to save user's access token into
database.

Design Database
~~~~~~~~~~~~~~~

Here is an example on database schema design with Flask-SQLAlchemy. We designed
two tables, one is for OAuth 1, one is for OAuth 2::

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

And then we can save user's access token into database when user was redirected
back to our ``/authorize`` page, like::

    @app.route('/authorize')
    def authorize():
        token = oauth.github.authorize_access_token()
        resp = oauth.github.get('user')
        profile = resp.json()
        user = User.get_by_github(profile)
        # implement save method yourself
        OAuth2Token.save('github', user, token)
        return redirect('/')

Connect Token to Current User
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You can always pass a ``token`` parameter to the remote application request
methods, like::

    oauth.twitter.get(url, token=token)
    oauth.twitter.post(url, token=token)
    oauth.twitter.put(url, token=token)
    oauth.twitter.delete(url, token=token)

There is another implicit way to apply the token into the remote application
requests. We can connect OAuth token to the current user so that you don't need
to pass ``token`` every time::

    def fetch_twitter_token():
        token = OAuth1Token.get(name='twitter', user_id=current_user.id)
        if token:
            return token.to_token()

    # we can registry this ``fetch_token`` with oauth.register
    oauth.register(
        'twitter',
        # ....
        fetch_token=fetch_twitter_token,
    )

Now you can access current logged in user's Twitter resource without passing
the ``token`` parameter::

    @app.route('/profile')
    @require_login
    def twitter_profile():
        resp = oauth.twitter.get('account/verify_credentials.json')
        profile = resp.json()
        return render_template('twitter.html', profile=profile)

Since the ``OAuth`` registry can contain many services, it would be good enough
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
            OAuth1Token.save(name, current_user, token)
        else:
            # this is a pseudo method, you need to implement it yourself
            OAuth2Token.save(name, current_user, token)
        return redirect(url_for('profile', name=name))

    @app.route('/profile/<name>')
    @require_login
    def profile(name):
        client = oauth.create_client(name)
        resp = client.get(get_profile_url(name))
        profile = resp.json()
        return render_template('profile.html', profile=profile)

We can share a ``fetch_token`` method at OAuth registry level when
initialization. Define a common ``fetch_token``::

    def fetch_token(name):
        if name in OAUTH1_SERVICES:
            token = OAuth1Token.get(name=name, user_id=current_user.id)
        else:
            token = OAuth2Token.get(name=name, user_id=current_user.id)
        if token:
            return token.to_token()

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
        token = OAuth2Token.get(name=name, user_id=current_user.id)
        if not token:
            token = OAuth2Token(name=name, user_id=current_user.id)
        token.token_type = token.get('token_type', 'bearer')
        token.access_token = token.get('access_token')
        token.refresh_token = token.get('refresh_token')
        token.expires_at = token.get('expires_at')
        db.session.add(token)
        db.session.commit()
        return token

    # pass ``update_token``
    oauth = OAuth(app, update_token=update_token)

    # or init app later
    oauth = OAuth(update_token=update_token)
    oauth.init_app(app)

    # or init everything later
    oauth = OAuth()
    oauth.init_app(app, update_token=update_token)


Code Challenge
--------------

Adding ``code_challenge`` provided by :ref:`specs/rfc7636` is simple. You
register your remote app with a ``code_challenge_method``::

    oauth.register('example',
        client_id='Example Client ID',
        client_secret='Example Client Secret',
        access_token_url='https://example.com/oauth/access_token',
        authorize_url='https://example.com/oauth/authorize',
        api_base_url='https://api.example.com/',
        client_kwargs=None,
        code_challenge_method='S256',
    )

Note, the only supported ``code_challenge_method`` is ``S256``.

Compliance Fix
--------------

The :class:`RemoteApp` is a subclass of :class:`~authlib.client.OAuthClient`,
they share the same logic for compliance fix. Construct a method to fix
requests session::

    def slack_compliance_fix(session):
        def _fix(resp):
            token = resp.json()
            # slack returns no token_type
            token['token_type'] = 'Bearer'
            resp._content = to_unicode(json.dumps(token)).encode('utf-8')
            return resp
        session.register_compliance_hook('access_token_response', _fix)

When :meth:`OAuth.register` a remote app, pass it in the parameters::

    oauth.register(
        'slack',
        client_id='...',
        client_secret='...',
        ...,
        compliance_fix=slack_compliance_fix,
        ...
    )

Find all the available compliance hooks at :ref:`compliance_fix_oauth2`.

Loginpass
---------

There are many built-in integrations served by loginpass_, checkout the
``flask_example`` in loginpass project. Here is an example of GitHub::

    from flask import Flask
    from authlib.flask.client import OAuth
    from loginpass import create_flask_blueprint, GitHub

    app = Flask(__name__)
    oauth = OAuth(app)

    def handle_authorize(remote, token, user_info):
        if token:
            save_token(remote.name, token)
        if user_info:
            save_user(user_info)
            return user_page
        raise some_error

    github_bp = create_flask_blueprint(GitHub, oauth, handle_authorize)
    app.register_blueprint(github_bp, url_prefix='/github')
    # Now, there are: ``/github/login`` and ``/github/auth``

The source code of loginpass is very simple, they are just preconfigured
services integrations.

.. _loginpass: https://github.com/authlib/loginpass
