.. _oauth_2_session:

OAuth 2 Session
===============

.. meta::
    :description: An OAuth 2 implementation for requests Session, powered
        by Authlib.

.. module:: authlib.client

The :class:`OAuth2Session` in Authlib is designed to be compatible
with the one in **requests-oauthlib**. This section is a guide on
how to obtain an access token in OAuth 2 flow.


OAuth2Session for Authorization Code
------------------------------------

There are two steps in OAuth 2 to obtain an access token with authorization
code grant type. Initialize the session for reuse::

    >>> from authlib.client import OAuth2Session
    >>> client_id = 'Your GitHub client ID'
    >>> client_secret = 'Your GitHub client secret'
    >>> scope = 'user:email'  # we want to fetch user's email
    >>> session = OAuth2Session(client_id, client_secret, scope=scope)

You can assign a ``redirect_uri`` in case you want to specify the callback
url.

Redirect to Authorization Endpoint
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Unlike OAuth 1, there is no request token. The first step is to jump to
the remote authorization server::

    >>> authorize_url = 'https://github.com/login/oauth/authorize'
    >>> uri, state = session.authorization_url(authorize_url)
    >>> print(uri)
    https://github.com/login/oauth/authorize?response_type=code&client_id=c..id&scope=user%3Aemail&state=d..t

The :meth:`OAuth2Session.authorization_url` returns a tuple of ``(uri, state)``,
in real project, you should save the state for later use.

Now head over to the generated authorization url, and grant the authorization.

.. _fetch_oauth2_access_token:

Fetch Access Token
~~~~~~~~~~~~~~~~~~

The authorization server will redirect you back to your site with a code and
state arguments::

    https://example.com/github?code=42..e9&state=d..t

Use :meth:`OAuth2Session.fetch_access_token` to obtain access token. This
method will also verify the state in case of CSRF attack::

    >>> authorization_response = 'https://example.com/github?code=42..e9&state=d..t'
    >>> access_token_url = 'https://github.com/login/oauth/access_token'
    >>> token = session.fetch_access_token(access_token_url, authorization_response=authorization_response)
    >>> print(token)
    {
        'access_token': 'e..ad',
        'token_type': 'bearer',
        'scope': 'user:email'
    }

Save this token to access users' protected resources.

In real project, this session can not be re-used since you are redirected to
another website. You need to create another session yourself::

    >>> state = restore_previous_state()
    >>> session = OAuth2Session(client_id, client_secret, state=state)
    >>> session.fetch_access_token(access_token_url, authorization_response=authorization_response)

Authlib has a built-in Flask/Django integration. Learn from them.

OAuth2Session for Implicit
--------------------------

OAuth2Session supports implicit grant type. It can fetch the access token with
the ``response_type`` of ``token``::

    >>> uri, state = session.authorization_url(authorize_url, response_type='token')

When authorization is granted, the response url would be something like::

    https://example.com/cb#access_token=2..WpA&state=xyz&token_type=bearer&expires_in=3600

Fetch access token from the fragment with :meth:`OAuth2Session.fetch_access_token`:

    >>> token = session.fetch_access_token(authorization_response=authorization_response)
    >>> # if you don't specify access token endpoint, it will fetch from fragment.
    >>> print(token)
    {'access_token': '2..WpA', 'token_type': 'bearer', 'expires_in': 3600}

.. note:: GitHub doesn't support ``token`` response type, try with other services.


OAuth2Session for Password
--------------------------

The ``password`` grant type is supported since Version 0.5. Use ``username``
and ``password`` to fetch the access token::

    >>> token = session.fetch_access_token(token_url, username='a-name', password='a-password')

OAuth2Session for Client Credentials
------------------------------------

The ``client_credentials`` grant type is supported since Version 0.5. If no
``code`` or no user info provided, it would be a ``client_credentials``
request. But it is suggested that you specify a ``grant_type`` for it::

    >>> token = session.fetch_access_token(token_url)
    >>> # or with grant_type
    >>> token = session.fetch_access_token(token_url, grant_type='client_credentials')

Client Authentication
---------------------

When fetching access token, the authorization server will require a client
authentication, which is usually a **Basic** HTTP authentication of client_id
and client_secret. :class:`OAuth2Session` is using this authenticate method
by default, which is::

    >>> from requests.auth import HTTPBasicAuth
    >>> auth = HTTPBasicAuth(client_id, client_secret)

If the authorization server requires other means of authentication, you can
construct an ``auth`` for requests, and pass it to ``fetch_access_token``::

    >>> auth = YourAuth(...)
    >>> token = session.fetch_access_token(token_url, auth=auth, ...)

Access Protected Resources
--------------------------

Now you can access the protected resources. If you re-use the session, you
don't need to do anything::

    >>> account_url = 'https://api.github.com/user'
    >>> resp = session.get(account_url)
    <Response [200]>
    >>> resp.json()
    {...}

The above is not the real flow, just like what we did in
:ref:`fetch_oauth2_access_token`, we need to create another session
ourselves::

    >>> token = restore_access_token_from_database()
    >>> # token is a dict which must contain ``access_token``, ``token_type``
    >>> session = OAuth2Session(client_id, client_secret, token=token)
    >>> account_url = 'https://api.github.com/user'
    >>> resp = session.get(account_url)

.. _compliance_fix_oauth2:

Compliance Fix for non Standard
-------------------------------

There are services that claimed they are providing OAuth API, but with a little
differences. Some services even return with the wrong Content Type. Compliance
hooks are provided to solve those problems:

* access_token_response: invoked before token parsing.
* refresh_token_response: invoked before refresh token parsing.
* protected_request: invoked before making a request.

For instance, linkedin is using a ``oauth2_access_token`` parameter in query
string to protect users' resources, let's fix it::

    from authlib.common.urls import add_params_to_uri

    def _non_compliant_param_name(url, headers, data):
        access_token = session.token.get('access_token')
        token = [('oauth2_access_token', access_token)]
        url = add_params_to_uri(url, token)
        return url, headers, data

    session.register_compliance_hook('protected_request',
                                     _non_compliant_param_name)

If you find a non standard OAuth 2 services, and you can't fix it. Please
report it in GitHub issues.


OAuth 2 OpenID Connect
----------------------

For services that support OpenID Connect, if a scope of ``openid`` is provided,
the authorization server will return a value of ``id_token`` in response::

    >>> from authlib.client import OAuth2Session
    >>> client_id = 'Your Google client ID'
    >>> client_secret = 'Your Google client secret'
    >>> scope = 'openid email profile'
    >>> session = OAuth2Session(client_id, client_secret, scope=scope)

At the last step of ``session.fetch_access_token``, the return value contains
a ``id_token``::

    >>> resp = session.fetch_access_token(...)
    >>> print(resp['id_token'])

This ``id_token`` is a JWS text, it can not be used unless it is parsed.
Authlib has provided tools for parsing and validating OpenID Connect id_token::

    >>> from authlib.specs.oidc import parse_id_token, validate_id_token
    >>> # GET keys from https://www.googleapis.com/oauth2/v3/certs
    >>> token, header = parse_id_token(resp['id_token'], keys)
    >>> validate_id_token(token, header=header, response_type='code', ...)

It can also be completed by one step with :meth:`~authlib.specs.oidc.verify_id_token`.

.. note::

   To use OpenID Connect, you need to install Authlib with RSA::

       $ pip install Authlib[crypto]

There is a built-in Google app which supports OpenID Connect, checkout the
source code in **authlib.clients.apps.google**.
