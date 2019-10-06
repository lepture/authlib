.. _httpx_client:


OAuth for HTTPX
===============

.. meta::
    :description: An OAuth 1.0 and OAuth 2.0 Client implementation for a next
        generation HTTP client for Python, including support for OpenID Connect
        and service account, powered by Authlib.

HTTPX is a next-generation HTTP client for Python. Authlib enables OAuth 1.0
and OAuth 2.0 for HTTPX with its :class:`OAuth1Session`, ``OAuth2Session``
and ``AssertionSession``.

.. note:: HTTPX is still in its "alpha" stage, use it with caution.

HTTPX OAuth 1.0
---------------

There are three steps in OAuth 1 to obtain an access token:

1. fetch a temporary credential
2. visit the authorization page
3. exchange access token with the temporary credential

It shares a common API design with :ref:`requests_client`.

Read the common guide of :ref:`oauth_1_session` to understand the whole OAuth
1.0 flow.

HTTPX OAuth 2.0
---------------


Async OAuth 1.0
---------------


Async OAuth 2.0
---------------
