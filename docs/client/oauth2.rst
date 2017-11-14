OAuth 2 Session
===============

.. module:: authlib.client

The :class:`OAuth2Session` in Authlib is designed to be compatible
with the one in **requests-oauthlib**. This section is a guide on
how to obtain an access token in OAuth 2 flow.

There are two steps in OAuth 2 to obtain an access token. Initialize
the session for reuse::

    >>> from authlib.client import OAuth2Session
    >>> client_id = 'Your GitHub client ID'
    >>> client_secret = 'Your GitHub client secret'
    >>> scope = 'user:email'  # we want to fetch user's email
    >>> session = OAuth2Session(client_id, client_secret, scope=scope)

You can assign a ``redirect_uri`` in case you want to specify the callback
url.

Redirect to Authorization Endpoint
----------------------------------

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
------------------

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

The Token Response Type
-----------------------

The default ``response_type`` is ``code``. There are other response types in
OAuth 2. Let's try ``token``::

    >>> uri, state = session.authorization_url(authorize_url, response_type='token')

When authorization is granted, the response url would be something like::

    https://example.com/cb#access_token=2..WpA&state=xyz&token_type=bearer&expires_in=3600

Fetch access token from the fragment with :meth:`OAuth2Session.fetch_access_token`:

    >>> token = session.fetch_access_token(authorization_response=authorization_response)
    >>> # if you don't specify access token endpoint, it will fetch from fragment.

.. note:: GitHub doesn't support ``token`` response type, try with other services.

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
    >>> session = OAuth2Session(client_key, client_secret, token=token)
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
