.. _oauth_client:

OAuthClient
===========

.. module:: authlib.client

A mixed OAuth 1 and OAuth 2 client, one to control them both. With
:class:`OAuthClient`, we make the authorization much similar. It is also the
base class for framework integrations.

:class:`OAuthClient` will automatically detect whether it is OAuth 1 or
OAuth 2 via its parameters. OAuth 1 has ``request_token_url``, while OAuth 2
doesn't.

OAuth 1 Flow
------------

Configure an OAuth 1 client with :class:`OAuthClient`::

    client = OAuthClient(
        client_key='Twitter Consumer Key',
        client_secret='Twitter Consumer Secret',
        request_token_url='https://api.twitter.com/oauth/request_token',
        access_token_url='https://api.twitter.com/oauth/access_token',
        authorize_url='https://api.twitter.com/oauth/authenticate',
        api_base_url='https://api.twitter.com/1.1/',
    )

There are other options that you could pass to the class. Please read the API
documentation.

Register Hooks
~~~~~~~~~~~~~~

For OAuth 1, we need to register four hooks:

* request_token_setter
* request_token_getter
* authorize_redirect
* access_token_getter

**request_token_setter** is used for saving request token for later use::

    def request_token_setter(token):
        session['token'] = token

    client.register_hook('request_token_setter', request_token_setter)

**request_token_getter** is used to fetch the request token that we saved
earlier::

    def request_token_getter():
        return session.pop('token', None)

    client.register_hook('request_token_getter', request_token_getter)

**authorize_redirect** is how we handle HTTP redirect to authorization server::

    def authorize_redirect(url, callback_uri, state):
        if callback_uri:
            # save it for later use
            session['callback_uri'] = callback_uri
        # state is not used in OAuth 1
        return redirect_response(url, status_code=302)

**access_token_getter** is a function to fetch access token from your database::

    def access_token_getter():
        # it should return a dict of:
        # {'oauth_token': '..', 'oauth_token_secret': '..'}
        return db.get_current_user_token()

Redirect to Authorization Endpoint
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

With your hooks configured, we can head over to the authorization server
directly, our request token hooks will handle everything well for us::

    client.authorize_redirect('https://api.twitter.com/oauth/authenticate')
    # The second ``callback_uri`` parameter is optional.

Now we will be redirect to the authorization endpoint with the hook you
provided in ``authorize_redirect``.

Get Access Token
~~~~~~~~~~~~~~~~

If permission is granted, we can fetch the access token now::

    callback_uri = session.pop('callback_uri', None)
    params = parse_response_url_qs()
    token = client.fetch_access_token(callback_uri, **params)
    save_token_to_db(token)

OAuth 2 Flow
------------

The flow of OAuth 2 is similar with OAuth 1, and much simpler::

    client = OAuthClient(
        client_key='GitHub Client ID',
        client_secret='GitHub Client Secret',
        api_base_url='https://api.github.com/',
        access_token_url='https://github.com/login/oauth/access_token',
        authorize_url='https://github.com/login/oauth/authorize',
        client_kwargs={'scope': 'user:email'},
    )

Register Hooks
~~~~~~~~~~~~~~

For OAuth 2, we only need to register two hooks:

* authorize_redirect
* access_token_getter

**authorize_redirect** is how we handle HTTP redirect to authorization server::

    def authorize_redirect(url, callback_uri, state):
        if callback_uri:
            # save it for later use
            session['callback_uri'] = callback_uri
        if state:
            session['state'] = state
        return redirect_response(url, status_code=302)

**access_token_getter** is a function to fetch access token from your database::

    def access_token_getter():
        # it should return a dict of:
        # {'access_token': '..', 'expires_at': '..'}
        return db.get_current_user_token()

Redirect to Authorization Endpoint
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

With your hooks configured, we can head over to the authorization server
directly, our request token hooks will handle everything well for us::

    callback_uri = 'https://example.com/auth'
    authorize_uri = 'https://github.com/login/oauth/authorize'
    client.authorize_redirect(authorize_uri, callback_uri)

Now we will be redirect to the authorization endpoint with the hook you
provided in ``authorize_redirect``.

Get Access Token
~~~~~~~~~~~~~~~~

It's the same as OAuth 1. If permission is granted, we can fetch the access
token now::

    callback_uri = session.pop('callback_uri', None)
    params = parse_response_url_qs()
    token = client.fetch_access_token(callback_uri, **params)
    save_token_to_db(token)

.. _compliance_fix_mixed:

Compliance Fix
--------------

Since many OAuth 2 providers are not following standard strictly, we need to
fix them. It has been introduced in :ref:`compliance_fix_oauth2`.

For OAuthClient, we can register our hooks one by one, with
:meth:`OAuth2Session.register_compliance_hook`::

    client.session.register_compliance_hook('protected_request', func)

However, there is a shortcut attribute for it. You need to construct a method
which takes ``session`` as the parameter::

    def compliance_fix(session):

        def fix_protected_request(url, headers, data):
            # do something
            return url, headers, data

        def fix_access_token_response(response):
            # patch response
            return response

        session.register_compliance_hook(
            'protected_request', fix_protected_request)
        session.register_compliance_hook(
            'access_token_response', fix_access_token_response)
        # register other hooks

Later, when you initialized **OAuthClient**, pass it to the client parameters::

    client = OAuthClient(
        client_key='...',
        client_secret='...',
        ...,
        compliance_fix=compliance_fix,
        ...
    )

It will automatically patch the requests session for OAuth 2.
