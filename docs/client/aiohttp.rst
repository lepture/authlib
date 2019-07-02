OAuth for aiohttp
=================

.. meta::
    :description: An OAuth 1 protocol implementation for
        aiohttp.ClientSession, powered by Authlib.

AsyncOAuth1Client for aiohttp
-----------------------------

.. versionadded:: v0.11
    This is an experimental feature.

The ``AsyncOAuth1Client`` is located in ``authlib.client.aiohttp``. Authlib doesn't
embed ``aiohttp`` as a dependency, you need to install it yourself.

Here is an example on how you can initialize an instance of ``AsyncOAuth1Client``
for ``aiohttp``::

    import asyncio
    from aiohttp import ClientSession
    from authlib.client.aiohttp import AsyncOAuth1Client, OAuthRequest

    REQUEST_TOKEN_URL = 'https://api.twitter.com/oauth/request_token'

    async def main():
        # OAuthRequest is required to handle auth
        async with ClientSession(request_class=OAuthRequest) as session:
            client = AsyncOAuth1Client(session, 'client_id', 'client_secret', ...)
            token = await client.fetch_request_token(REQUEST_TOKEN_URL)
            print(token)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())

The API is similar with ``OAuth1Session`` above. Using the ``client`` for the
three steps authorization:

Fetch Temporary Credential
~~~~~~~~~~~~~~~~~~~~~~~~~~

The first step is to fetch temporary credential, which will be used to generate
authorization URL::

    request_token_url = 'https://api.twitter.com/oauth/request_token'
    request_token = await client.fetch_request_token(request_token_url)
    print(request_token)
    {'oauth_token': 'gA..H', 'oauth_token_secret': 'lp..X', 'oauth_callback_confirmed': 'true'}

Save this temporary credential for later use (if required).

Redirect to Authorization Endpoint
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The second step is to generate the authorization URL::

    authenticate_url = 'https://api.twitter.com/oauth/authenticate'
    url = client.create_authorization_url(authenticate_url, request_token['oauth_token'])
    print(url)
    'https://api.twitter.com/oauth/authenticate?oauth_token=gA..H'

Actually, the second parameter ``request_token`` can be omitted, since session
is re-used::

    url = client.create_authorization_url(authenticate_url)
    print(url)
    'https://api.twitter.com/oauth/authenticate?oauth_token=gA..H'

Fetch Access Token
~~~~~~~~~~~~~~~~~~

When the authorization is granted, you will be redirected back to your
registered callback URI. For instance::

    https://example.com/twitter?oauth_token=gA..H&oauth_verifier=fcg..1Dq

If you assigned ``redirect_uri`` in :ref:`fetch_oauth1_access_token`, the
authorize response would be something like::

    https://your-domain.org/auth?oauth_token=gA..H&oauth_verifier=fcg..1Dq

In the production flow, you may need to create a new instance of
``AsyncOAuth1Client``, it is the same as above. You need to use the previous
request token to exchange an access token::

    # twitter redirected back to your website
    resp_url = 'https://example.com/twitter?oauth_token=gA..H&oauth_verifier=fcg..1Dq'

    # you may use the ``oauth_token`` in resp_url to
    # get back your previous request token
    request_token = {'oauth_token': 'gA..H', 'oauth_token_secret': '...'}

    # assign request token to client
    client.token = request_token

    # resolve the ``oauth_verifier`` from resp_url
    oauth_verifier = get_oauth_verifier_value(resp_url)

    access_token_url = 'https://api.twitter.com/oauth/access_token'
    token = await client.fetch_access_token(access_token_url, oauth_verifier)

You can save the ``token`` to access protected resources later.


Access Protected Resources
~~~~~~~~~~~~~~~~~~~~~~~~~~

Now you can access the protected resources. Usually, you will need to create
an instance of ``AsyncOAuth1Client``::

    # get back the access token if you have saved it in some place
    access_token = {'oauth_token': '...', 'oauth_secret': '...'}

    # assign it to client
    client.token = access_token

    account_url = 'https://api.twitter.com/1.1/account/verify_credentials.json'
    async with client.get(account_url) as resp:
        data = await resp.json()

Notice, it is also possible to create the client instance with access token at
the initialization::

    client = AsyncOAuth1Client(
        session, 'client_id', 'client_secret',
        token='...', token_secret='...',
        ...
    )


AsyncOAuth2Client for aiohttp
-----------------------------

.. versionadded:: v0.11
    This is an experimental feature.


AsyncAssertionClient for aiohttp
--------------------------------

.. versionadded:: v0.12
    This is an experimental feature.

The ``AsyncAssertionClient`` is located in ``authlib.client.aiohttp``. Authlib
doesn't embed ``aiohttp`` as a dependency, you need to install it yourself. It
will create a session for Assertion Framework of OAuth 2.0 Authorization Grants.
This is also know as service account.

Take `Google Service Account`_ as an example, with the information in your
service account JSON configure file::

    import json
    import asyncio
    from aiohttp import ClientSession
    from authlib.client.aiohttp import OAuthRequest, AsyncAssertionClient

    with open('MyProject-1234.json') as f:
        conf = json.load(f)

    token_url = conf['token_uri']
    header = {'alg': 'RS256'}
    key_id = conf.get('private_key_id')
    if key_id:
        header['kid'] = key_id

    # Google puts scope in payload
    claims = {'scope': scope}

    async def main():
        async with ClientSession(request_class=OAuthRequest) as session:
            client = AsyncAssertionClient(
                session,
                token_url=token_url,
                issuer=conf['client_email'],
                audience=token_url,
                claims=claims,
                subject=None,
                key=conf['private_key'],
                header=header,
            )
            await client.get(...)
            await client.post(...)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())


.. _`Google Service Account`: https://developers.google.com/identity/protocols/OAuth2ServiceAccount
