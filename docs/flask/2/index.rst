.. _flask_oauth2_server:

Flask OAuth 2.0 Server
======================

.. meta::
    :description: How to create an OAuth 2.0 server in Flask with Authlib.
        And understand how OAuth 2.0 works. Authlib has all built-in grant
        types for you.

This section is not a step by step guide on how to create an OAuth 2.0 server
in Flask. Instead, we will learn how the Flask implementation works, and some
technical details in an OAuth 2.0 provider.

If you need a quick example, here are the official tutorial guide and examples
on GitHub:

1. `Example of OAuth 2.0 server <https://github.com/authlib/example-oauth2-server>`_
2. Example of OpenID Connect server (not ready)

At the very beginning, we need to have some basic understanding of the OAuth 2.0
specification. Read :ref:`specs/rfc6749` at first.

.. important::

    If you are developing on your localhost, remember to set the environment
    variable::

        export AUTHLIB_INSECURE_TRANSPORT=true

Looking for OAuth 2 client? Check out :ref:`flask_client`.

.. toctree::
    :maxdepth: 2

    authorization-server
    grants
    endpoints
    resource-server
    openid-connect
