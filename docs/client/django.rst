.. _django_client:

Django OAuth Client
===================

.. meta::
    :description: The built-in Django integrations for OAuth 1.0 and
        OAuth 2.0 clients.

.. module:: authlib.django.client

Looking for OAuth providers?

- :ref:`django_oauth1_server`
- OAuth 2 provider is not ready

The Django client shares a similar API with Flask client. But there are
differences, since Django has no request context, you need to pass ``request``
argument yourself.

Create a registry with :class:`OAuth` object::

    from authlib.django.client import OAuth

    oauth = OAuth()

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
pair can be omit. They can be configured from your Django settings::

    AUTHLIB_OAUTH_CLIENTS = {
        'twitter': {
            'client_id': 'Twitter Consumer Key',
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

The ``client_kwargs`` is a dict configuration to pass extra parameters to
``OAuth1Session``. If you are using ``RSA-SHA1`` signature method::

    client_kwargs = {
        'signature_method': 'RSA-SHA1',
        'signature_type': 'HEADER',
        'rsa_key': 'Your-RSA-Key'
    }

Saving Temporary Credential
~~~~~~~~~~~~~~~~~~~~~~~~~~~

In OAuth 1.0, we need to use a temporary credential to exchange access token,
this temporary credential was created before redirecting to the provider (Twitter),
we need to save this temporary credential somewhere in order to use it later.

In OAuth 1, Django client will save the request token in sessions. In this
case, you just need to configure Session Middleware in Django::

    MIDDLEWARE = [
        'django.contrib.sessions.middleware.SessionMiddleware'
    ]

Follow the official Django documentation to set a proper session. Either a
database backend or a cache backend would work well.

.. warning::

    Be aware, using secure cookie as session backend will expose your request
    token.

Routes for Authorization
~~~~~~~~~~~~~~~~~~~~~~~~

After configuration of ``OAuth`` registry and the remote application, the
rest steps are much simpler. The only required parts are routes:

1. redirect to 3rd party provider (Twitter) for authentication
2. redirect back to your website to fetch access token and profile

Here is the example for Twitter login::

    def login(request):
        # build a full authorize callback uri
        redirect_uri = request.build_absolute_uri('/authorize')
        return oauth.twitter.authorize_redirect(request, redirect_uri)

    def authorize(request):
        token = oauth.twitter.authorize_access_token(request)
        resp = oauth.twitter.get('account/verify_credentials.json')
        profile = resp.json()
        # do something with the token and profile
        return '...'

After user confirmed on Twitter authorization page, it will redirect
back to your website ``authorize`` page. In this route, you can get your
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
pair can be omit. They can be configured from your Django settings::

    AUTHLIB_OAUTH_CLIENTS = {
        'github': {
            'client_id': 'GitHub Client ID',
            'client_secret': 'GitHub Client Secret',
            'access_token_url': 'https://github.com/login/oauth/access_token',
            'authorize_url': 'https://github.com/login/oauth/authorize',
            'api_base_url': 'https://api.github.com/',
            'client_kwargs': {'scope': 'user:email'}
        }
    }

The ``client_kwargs`` is a dict configuration to pass extra parameters to
``OAuth2Session``, you can pass extra parameters like::

    client_kwargs = {
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


    def login(request):
        # build a full authorize callback uri
        redirect_uri = request.build_absolute_uri('/authorize')
        return oauth.github.authorize_redirect(request, redirect_uri)

    def authorize(request):
        token = oauth.github.authorize_access_token(request)
        resp = oauth.github.get('user')
        profile = resp.json()
        # do something with the token and profile
        return '...'

After user confirmed on GitHub authorization page, it will redirect
back to your website ``authorize``. In this route, you can get your
user's GitHub profile information, you can store the user information
in your database, mark your user as logged in and etc.


Accessing OAuth Resources
-------------------------

There are also chances that you need to access your user's 3rd party
OAuth provider resources. For instance, you want to display your user's
GitHub profile::

    def github_profile(request):
        token = OAuth2Token.objects.get(
            name='github',
            user=request.user
        )
        # API URL: https://api.github.com/user
        resp = oauth.github.get('user', token=token.to_token())
        profile = resp.json()
        return render_template('github.html', profile=profile)

In this case, we need a place to store the access token in order to use
it later. Take an example, we want to save user's access token into
database.


Design Database
~~~~~~~~~~~~~~~

Authlib Django client has no built-in database model. You need to design the
Token model by yourself. This is designed by intention.

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

And then we can save user's access token into database when user was redirected
back to our ``authorize`` page, like::

    def authorize(request):
        token = oauth.github.authorize_access_token(request)
        # OAuth2Token.save('github', token)
        return redirect('/')

Connect Token to Current User
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You can always pass a ``token`` parameter to the remote application request
methods, like::

    oauth.twitter.get(url, token=token)
    oauth.twitter.post(url, token=token)
    oauth.twitter.put(url, token=token)
    oauth.twitter.delete(url, token=token)

But it is a little waste of code each time to fetch the token like::

    data = OAuth2Token.objects.get(
            name='github',
            user=request.user
    )
    token = data.to_token()

Instead, you can implement a ``fetch_token`` method to do that. You don't have
to fetch token every time, you can just pass the ``request`` instance::

    def fetch_twitter_token(request):
        item = OAuth1Token.objects.get(
            name='twitter',
            user=request.user
        )
        return item.to_token()

    # we can registry this ``fetch_token`` with oauth.register
    oauth.register(
        'twitter',
        # ...
        fetch_token=fetch_twitter_token,
    )

Developers can also pass the ``fetch_token`` to ``OAuth`` registry so that
they don't have to pass a ``fetch_token`` for each remote app. In this case,
the ``fetch_token`` will accept two parameters::

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
register your remote app with a ``code_challenge_method``::

    oauth.register(
        'example',
        client_id='Example Client ID',
        client_secret='Example Client Secret',
        access_token_url='https://example.com/oauth/access_token',
        authorize_url='https://example.com/oauth/authorize',
        api_base_url='https://api.example.com/',
        client_kwargs=None,
        code_challenge_method='S256',
    )

Note, the only supportted ``code_challenge_method`` is ``S256``.

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
``django_example`` in loginpass project. Here is an example of GitHub::

    from authlib.django.client import OAuth
    from loginpass import create_django_urlpatterns, GitHub

    oauth = OAuth()

    def handle_authorize(request, remote, token, user_info):
        if token:
            save_token(request, remote.name, token)
        if user_info:
            save_user(request, user_info)
            return user_page
        raise some_error

    oauth_urls = create_django_urlpatterns(GitHub, oauth, handle_authorize)


    # Register it in ``urls.py``
    from django.urls import include, path

    urlpatterns = [...]
    urlpatterns.append(path('/github/', include(oauth_urls)))
    # Now, there are: ``/github/login`` and ``/github/auth``

The source code of loginpass is very simple, they are just preconfigured
services integrations.

.. _loginpass: https://github.com/authlib/loginpass
