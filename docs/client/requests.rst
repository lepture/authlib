.. _requests_client:


OAuth for Requests
==================

.. meta::
    :description: An OAuth 1.0 and OAuth 2.0 Client implementation for Python requests,
        including support for OpenID Connect and service account, powered by Authlib.

.. module:: authlib.integrations.requests_client
    :noindex:

Requests is a very popular HTTP library for Python. Authlib enables OAuth 1.0
and OAuth 2.0 for Requests with its :class:`OAuth1Session`, :class:`OAuth2Session`
and :class:`AssertionSession`.


Requests OAuth 1.0
------------------

There are three steps in :ref:`oauth_1_session` to obtain an access token:

1. fetch a temporary credential
2. visit the authorization page
3. exchange access token with the temporary credential

It shares a common API design with :ref:`httpx_client`.

Read the common guide of :ref:`oauth_1_session` to understand the whole OAuth
1.0 flow.


Requests OAuth 2.0
------------------

In :ref:`oauth_2_session`, there are many grant types, including:

1. Authorization Code Flow
2. Implicit Flow
3. Password Flow
4. Client Credentials Flow

And also, Authlib supports non Standard OAuth 2.0 providers via Compliance Fix.

Read the common guide of :ref:`oauth_2_session` to understand the whole OAuth
2.0 flow.


Requests OpenID Connect
-----------------------

OpenID Connect is built on OAuth 2.0. It is pretty simple to communicate with
an OpenID Connect provider via Authlib. With Authlib built-in OAuth 2.0 system
and JsonWebToken (JWT), parsing OpenID Connect ``id_token`` could be very easy.

Understand how it works with :ref:`oidc_session`.


Requests Service Account
------------------------

The Assertion Framework of OAuth 2.0 Authorization Grants is also known as
service account. With the implementation of :class:`AssertionSession`, we can
easily integrate with a "assertion" service.

Checking out an example of Google Service Account with :ref:`assertion_session`.
