.. _fastapi_client:

FastAPI OAuth Client
====================

.. meta::
    :description: Use Authlib built-in Starlette integrations to build
        OAuth 1.0, OAuth 2.0 and OpenID Connect clients for FastAPI.

.. module:: authlib.integrations.starlette_client
    :noindex:

FastAPI_ is a modern, fast (high-performance), web framework for building
APIs with Python 3.6+ based on standard Python type hints. It is build on
top of **Starlette**, that means most of the code looks similar with
Starlette code. You should first read documentation of:

1. :ref:`frameworks_clients`
2. :ref:`starlette_client`

Here is how you would create a FastAPI application::

    from fastapi import FastAPI
    from starlette.middleware.sessions import SessionMiddleware

    app = FastAPI()
    # we need this to save temporary code & state in session
    app.add_middleware(SessionMiddleware, secret_key="some-random-string")

Since Authlib starlette requires using ``request`` instance, we need to
expose that ``request`` to Authlib. According to the documentation on
`Using the Request Directly <https://fastapi.tiangolo.com/tutorial/using-request-directly/>`_::

    from starlette.requests import Request

    @app.get("/login")
    def login_via_google(request: Request):
        redirect_uri = 'https://example.com/auth'
        return await oauth.google.authorize_redirect(request, redirect_uri)

    @app.get("/auth")
    def auth_via_google(request: Request):
        token = await oauth.google.authorize_access_token(request)
        user = await oauth.google.parse_id_token(request, token)
        return dict(user)

.. _FastAPI: https://fastapi.tiangolo.com/

All other APIs are the same with Starlette.

FastAPI OAuth 1.0 Client
------------------------

We have a blog post about how to create Twitter login in FastAPI:
https://blog.authlib.org/2020/fastapi-twitter-login

FastAPI OAuth 2.0 Client
------------------------

We have an example about Google login here:

https://github.com/authlib/demo-oauth-client/tree/master/fastapi-google-login
