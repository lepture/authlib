.. _oauth_1_session:

OAuth 1 Session
===============

.. meta::
   :description: An OAuth 1 implementation for requests Session, powered
        by Authlib.

.. module:: authlib.client

The :class:`OAuth1Session` in Authlib is designed to be
compatible with the one in **requests-oauthlib**, although there are
differences. This section is a guide on how to obtain an access token
in OAuth 1 flow.

There are three steps in OAuth 1 to obtain an access token. Initialize
the session for reuse::

    >>> from authlib.client import OAuth1Session
    >>> client_key = 'Your Twitter client key'
    >>> client_secret = 'Your Twitter client secret'
    >>> session = OAuth1Session(client_key, client_secret)

.. _fetch_request_token:

Fetch Request Token
-------------------

The first step is to fetch request token, which will be used to generate
authorization URL::

    >>> request_token_url = 'https://api.twitter.com/oauth/request_token'
    >>> request_token = session.fetch_request_token(request_token_url)
    >>> print(request_token)
    {'oauth_token': 'gA..H', 'oauth_token_secret': 'lp..X', 'oauth_callback_confirmed': 'true'}

Save this request token for later use (if required).

You can assign a ``callback_uri`` before fetching the request token, if
you want to redirect back to another URL other than the one you registered::

    >>> session.callback_uri = 'https://your-domain.org/auth'
    >>> session.fetch_request_token(request_token_url)

Redirect to Authorization Endpoint
----------------------------------

The second step is to generate the authorization URL::

    >>> authenticate_url = 'https://api.twitter.com/oauth/authenticate'
    >>> session.authorization_url(authenticate_url, request_token['oauth_token'])
    'https://api.twitter.com/oauth/authenticate?oauth_token=gA..H'

Actually, the second parameter ``request_token`` can be omitted, since session
is re-used::

    >>> session.authorization_url(authenticate_url)

Now visit the authorization url that :meth:`OAuth1Session.authorization_url`
generated, and grant the authorization.

.. _fetch_oauth1_access_token:

Fetch Access Token
------------------

When the authorization is granted, you will be redirected back to your
registered callback URI. For instance::

    https://example.com/twitter?oauth_token=gA..H&oauth_verifier=fcg..1Dq

If you assigned ``callback_uri`` in :ref:`fetch_oauth1_access_token`, the
authorize response would be something like::

    https://your-domain.org/auth?oauth_token=gA..H&oauth_verifier=fcg..1Dq

Now fetch the access token with this response::

    >>> resp_url = 'https://example.com/twitter?oauth_token=gA..H&oauth_verifier=fcg..1Dq'
    >>> session.parse_authorization_response(resp_url)
    >>> access_token_url = 'https://api.twitter.com/oauth/access_token'
    >>> token = session.fetch_access_token(access_token_url)
    >>> print(token)
    {
        'oauth_token': '12345-st..E',
        'oauth_token_secret': 'o67..X',
        'user_id': '12345',
        'screen_name': 'lepture',
        'x_auth_expires': '0'
    }

Save this token to access protected resources.

The above flow is not always what we will use in real project. When we are
redirected to authorization endpoint, our session is over. In this case, when
the authorization server send us back to our server, we need to create another
session::

    >>> # restore your saved request token
    >>> request_token = restore_request_token_back()
    >>> resource_owner_key = request_token['oauth_token']
    >>> resource_owner_secret = request_token['oauth_token_secret']
    >>> session = OAuth1Session(
    ...     client_key, client_secret,
    ...     resource_owner_key=resource_owner_key,
    ...     resource_owner_secret=resource_owner_secret)
    >>> # there is no need for `parse_authorization_response` if you can get `verifier`
    >>> verifier = request.args.get('verifier')
    >>> access_token_url = 'https://api.twitter.com/oauth/access_token'
    >>> token = session.fetch_access_token(access_token_url, verifier)

Access Protected Resources
--------------------------

Now you can access the protected resources. If you re-use the session, you
don't need to do anything::

    >>> account_url = 'https://api.twitter.com/1.1/account/verify_credentials.json'
    >>> resp = session.get(account_url)
    <Response [200]>
    >>> resp.json()
    {...}

The above is not the real flow, just like what we did in
:ref:`fetch_oauth1_access_token`, we need to create another session ourselves::

    >>> access_token = restore_access_token_from_database()
    >>> resource_owner_key = access_token['oauth_token']
    >>> resource_owner_secret = access_token['oauth_token_secret']
    >>> session = OAuth1Session(
    ...     client_key, client_secret,
    ...     resource_owner_key=resource_owner_key,
    ...     resource_owner_secret=resource_owner_secret)
    >>> account_url = 'https://api.twitter.com/1.1/account/verify_credentials.json'
    >>> resp = session.get(account_url)

Understand OAuth 1
------------------

To understand/feel the OAuth 1 authorization flow, register a Twitter consumer
client at https://apps.twitter.com/ and repeat the steps in this section.

Please note, there are duplicated steps in the documentation, read carefully
and ignore the duplicated explains.
