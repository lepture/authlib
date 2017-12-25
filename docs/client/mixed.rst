.. _oauth_client:

OAuthClient
===========

.. meta::
   :description: A mixed OAuth 1 and OAuth 2 client, one to control everything.
      The foundation for Flask and Django integrations.

.. module:: authlib.client

A mixed OAuth 1 and OAuth 2 client, one to control them both. With
:class:`OAuthClient`, we make the authorization much similar. It is the
base class for framework integrations.

:class:`OAuthClient` will automatically detect whether it is OAuth 1 or
OAuth 2 via its parameters. OAuth 1 has ``request_token_url``, while OAuth 2
doesn't.

To use **OAuthClient** for requesting user resources, you need to subclass it,
and implement a :meth:`OAuthClient.get_token` method::

    class MyOAuthClient(OAuthClient):
        def get_token(self):
            return get_current_user_token()

.. note:: This ``OAuthClient`` is designed for framework integrations, you
   won't use it in daily life.

OAuth 1 Flow
------------

Configure an OAuth 1 client with :class:`OAuthClient`::

    client = OAuthClient(
        client_id='Twitter Consumer Key',
        client_secret='Twitter Consumer Secret',
        request_token_url='https://api.twitter.com/oauth/request_token',
        access_token_url='https://api.twitter.com/oauth/access_token',
        authorize_url='https://api.twitter.com/oauth/authenticate',
        api_base_url='https://api.twitter.com/1.1/',
    )

There are other options that you could pass to the class. Please read the API
documentation.

Redirect to Authorization Endpoint
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

There is a request token exchange in OAuth 1, in this case, we need to save
the request token before heading over to authorization endpoint::

    def save_request_token(token):
        session['token'] = token

    # The first ``callback_uri`` parameter is optional.
    url, state = client.generate_authorize_redirect(
        save_request_token=save_request_token)

Now we will get a redirect url to the authorization endpoint. The return value
is a tuple of ``(url, state)``, in OAuth 1, ``state`` will always be ``None``.

Get Access Token
~~~~~~~~~~~~~~~~

If permission is granted, we can fetch the access token now::

    def get_request_token():
        return session.pop('token', None)

    callback_uri = session.pop('callback_uri', None)
    params = parse_response_url_qs()
    token = client.fetch_access_token(
        callback_uri, get_request_token=get_request_token, **params)
    save_token_to_db(token)

OAuth 2 Flow
------------

The flow of OAuth 2 is similar with OAuth 1, and much simpler::

    client = OAuthClient(
        client_id='GitHub Client ID',
        client_secret='GitHub Client Secret',
        api_base_url='https://api.github.com/',
        access_token_url='https://github.com/login/oauth/access_token',
        authorize_url='https://github.com/login/oauth/authorize',
        client_kwargs={'scope': 'user:email'},
    )


Redirect to Authorization Endpoint
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Unlike OAuth 1, there is no request token. The process to authorization
server is very simple::

    callback_uri = 'https://example.com/auth'
    url, state = client.generate_authorize_redirect(callback_uri)
    # save state for getting access token
    session['state'] = state

Note that, in OAuth 2, there will be a ``state`` always, you need to save it
for later use.

Get Access Token
~~~~~~~~~~~~~~~~

It's the same as OAuth 1. If permission is granted, we can fetch the access
token now::

    callback_uri = session.pop('callback_uri', None)
    params = parse_response_url_qs()
    # you need to verify state here
    assert params['state'] == session.pop('state')
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
        client_id='...',
        client_secret='...',
        ...,
        compliance_fix=compliance_fix,
        ...
    )

It will automatically patch the requests session for OAuth 2.
