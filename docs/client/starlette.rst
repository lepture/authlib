.. _starlette_client:

Starlette OAuth Client
===================

.. meta::
    :description: The built-in Starlette integrations for OAuth 1.0 and
        OAuth 2.0 clients.

.. module:: authlib.integrations.starlette_client
    :noindex:

The Starlette client provides integration with the Starlette ASGI framework and
can also be used with third party packages such as FastAPI and Bocadillo which
are built on top of Starlette.

The Starlette client shares a similar API with Flask client. But there are
differences, since Starlette has no request context, you need to pass in
instances of the Starlette ``Request`` object to the methods of the client.

Unlike the Flask and Django clients, the Starlette client does not contain
functionality to be configured from the application settings or object.

Create a registry with :class:`OAuth` object::

    from authlib.integrations.starlette_client import OAuth

    oauth = OAuth()

The common use case for OAuth is authentication, e.g. let your users log in
with Twitter, GitHub, Google etc.

Log In with OAuth 1.0
---------------------

For example, Twitter is an OAuth 1.0 service, you want your users to log in
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

The ``client_kwargs`` is a dict configuration to pass extra parameters to
``OAuth1Session``. If you are using ``RSA-SHA1`` signature method::

    client_kwargs = {
        'signature_method': 'RSA-SHA1',
        'signature_type': 'HEADER',
        'rsa_key': 'Your-RSA-Key'
    }

Saving Temporary Credentials
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

With OAuth 1.0, we need to use a temporary credential to exchange for an access token.
This temporary credential is created before redirecting to the provider (Twitter),
and needs to be saved somewhere in order to use it later.

With OAuth 1, the Starlette client will save the request token in sessions. To
enable this, we need to add the ``SessionMiddleware`` middleware to the
application, which requires the installation of the ``itsdangerous`` package::

    from starlette.applications import Starlette
    from starlette.middleware.sessions import SessionMiddleware
    app = Starlette()
    app.add_middleware(SessionMiddleware, secret_key="xxxxx")


.. warning::

    Using the ``SessionMiddleware`` will store the temporary credential as a
    secure cookie which will expose your request token to the client.

Routes for Authorization
~~~~~~~~~~~~~~~~~~~~~~~~

After the configuration of the ``OAuth`` registry and the remote application, it
is necessary to created the required routes and their associated functions. This
requires two routes:

1. A route to redirect to the 3rd party provider (Twitter) for authentication
2. A route to redirect back to your website to fetch the access token and user
   profile

Here is the example for Twitter login::

    from urllib.parse import urljoin, urlunsplit

    def login(request: Request):
        # build a full authorize callback uri
        u = urlunsplit(request.url.components)
        redirect_uri = urljoin(u, app.url_path_for("authorize"))
        return oauth.twitter.authorize_redirect(request, redirect_uri)

    def authorize(request: Request):
        token = oauth.twitter.authorize_access_token(request)
        resp = oauth.twitter.get('account/verify_credentials.json')
        profile = resp.json()
        # do something with the token and profile
        return '...'

After the user authenticates on the Twitter authorization page, they will be
redirected back to your website ``authorize`` page. In this route function, you
can get your user's twitter profile information, you can store the user
information in your database, mark your user as logged in etc.


Using OAuth 2.0 to Log In
-------------------------

For example, you want to use GitHub, which is an OAuth 2.0 service, to
authenticate users for your API.

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

The ``client_kwargs`` is a configuration ``dict`` object to pass extra
parameters to ``OAuth2Session``::

    client_kwargs = {
        'scope': 'profile',
        'token_endpoint_auth_method': 'client_secret_basic',
        'token_placement': 'header',
    }

There are several ``token_endpoint_auth_method`` methods detailed in
:ref:`client_auth_methods`.


Routes for Authorization
~~~~~~~~~~~~~~~~~~~~~~~~

After the configuration of the ``OAuth`` registry and the remote application, it
is necessary to created the required routes and their associated functions. This
requires two routes:

1. A route to redirect to the 3rd party provider (Twitter) for authentication
2. A route to redirect back to your website to fetch the access token and user
   profile

Here is the example for GitHub login::

    from urllib.parse import urljoin, urlunsplit

    def login(request: Request):
        # build a full authorize callback uri
        u = urlunsplit(request.url.components)
        redirect_uri = urljoin(u, app.url_path_for("authorize"))
        return oauth.github.authorize_redirect(request, redirect_uri)

    def authorize(request: Request):
        token = oauth.github.authorize_access_token(request)
        resp = oauth.github.get('user')
        profile = resp.json()
        # do something with the token and profile
        return '...'

After the user authenticates on the Twitter authorization page, they will be
redirected back to your website ``authorize`` page. In this route function, you
can get your user's twitter profile information, you can store the user
information in your database, mark your user as logged in etc.

Accessing OAuth Resources
-------------------------

It is possible to access your user's 3rd party OAuth provider resources, such as
their user profile::

    def github_profile(request):
        token = OAuth2Token.objects.get(
            name='github',
            user=request.user
        )
        # API URL: https://api.github.com/user
        resp = oauth.github.get('user', token=token.to_token())
        profile = resp.json()
        return render_template('github.html', profile=profile)

In this case, we need a place to store the access token in order to use it
later. For example, we may chose to store the access token server side in in a
database.


Database design for storing user access tokens
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The Authlib Starlette client has no built-in database model, and so it is necessary to
design a suitable Token model.

Here are some hints on how to design your schema::

    class OAuth1Token(models.Model):
        name = models.CharField(max_length=40)
        oauth_token = models.CharField(max_length=200)
        oauth_token_secret = models.CharField(max_length=200)
        # ...

        def to_token(self):
            return dict(
                oauth_token=self.access_token,
                oauth_token_secret=self.alt_token,
            )

    class OAuth2Token(models.Model):
        name = models.CharField(max_length=40)
        token_type = models.CharField(max_length=20)
        access_token = models.CharField(max_length=200)
        refresh_token = models.CharField(max_length=200)
        # oauth 2 expires time
        expires_at = models.DateTimeField()
        # ...

        def to_token(self):
            return dict(
                access_token=self.access_token,
                token_type=self.token_type,
                refresh_token=self.refresh_token,
                expires_at=self.expires_at,
            )

And then we can save user's access token into the database when the user was redirected
back to our ``authorize`` page::

    def authorize(request):
        token = oauth.github.authorize_access_token(request)
        # OAuth2Token.save('github', token)
        return RedirectResponse('/')

Connect Token to Current User
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You can always pass a ``token`` parameter to the remote application request
methods like this::

    oauth.twitter.get(url, token=token)
    oauth.twitter.post(url, token=token)
    oauth.twitter.put(url, token=token)
    oauth.twitter.delete(url, token=token)

And then you will need to fetch the token::

    data = OAuth2Token.objects.get(
            name='github',
            user=request.user
    )
    token = data.to_token()

However, it is more convenient to implement a ``fetch_token`` method to do this, since uou won't have
to fetch the token every time, but instead pass the ``request`` instance::

    def fetch_twitter_token(request):
        item = OAuth1Token.objects.get(
            name='twitter',
            user=request.user
        )
        return item.to_token()

    # we can register this ``fetch_token`` with oauth.register
    oauth.register(
        'twitter',
        # ...
        fetch_token=fetch_twitter_token,
    )

It's also possible to pass the ``fetch_token`` to ``OAuth`` registry so that
it's not necessary to pass a ``fetch_token`` for each remote app registration.
In this case, the ``fetch_token`` will accept two parameters::

    def fetch_token(name, request):
        if name in OAUTH1_SERVICES:
            model = OAuth1Token
        else:
            model = OAuth2Token

        item = model.objects.get(
            name=name,
            user=request.user
        )
        return item.to_token()

    oauth = OAuth(fetch_token=fetch_token)

Now, developers don't have to pass a ``token`` in the HTTP requests,
instead, they can pass the ``request``::

    def fetch_resource(request):
        resp = oauth.twitter.get('account/verify_credentials.json', request=request)
        profile = resp.json()
        # ...

Code Challenge
--------------

Adding ``code_challenge`` provided by :ref:`specs/rfc7636` is simple. You
register your remote app with a ``code_challenge_method`` in ``client_kwargs``::

    oauth.register(
        'example',
        client_id='Example Client ID',
        client_secret='Example Client Secret',
        access_token_url='https://example.com/oauth/access_token',
        authorize_url='https://example.com/oauth/authorize',
        api_base_url='https://api.example.com/',
        client_kwargs={'code_challenge_method': 'S256'},
    )

Note, the only supportted ``code_challenge_method`` is ``S256``.

Compliance Fix
--------------

The :class:`RemoteApp` is a subclass of :class:`~authlib.client.OAuthClient`,
they share the same logic for compliance fix. Construct a method to fix
the ``session`` attribute of a ``Request`` instance::

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

loginpass_ does not currently support Starlette. A pull request adding support
to loginpass_ would be welcome.

.. _loginpass: https://github.com/authlib/loginpass
