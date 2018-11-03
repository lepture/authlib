.. Authlib documentation master file, created by
   sphinx-quickstart on Wed Nov  1 11:04:52 2017.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Authlib: Python Authentication
==============================

Release v\ |version|. (:ref:`Installation <install>`)

The ultimate Python library in building OAuth and OpenID Connect servers.
It is designed from low level specifications implementations to high level
frameworks integrations, to meet the needs of everyone.

Authlib is compatible with Python2.7+ and Python3.5+.

Overview
--------

A simple :ref:`flask_client` which connects to the Github OAuth2 API::

    from flask import Flask
    from authlib.flask.client import OAuth
    # use loginpass to make OAuth connection simpler
    from loginpass import create_flask_blueprint, GitHub

    app = Flask(__name__)
    oauth = OAuth(app)

    def handle_authorize(remote, token, user_info):
        if token:
            save_token(remote.name, token)
        if user_info:
            save_user(user_info)
            return user_page
        raise some_error

    github_bp = create_flask_blueprint(GitHub, oauth, handle_authorize)
    app.register_blueprint(github_bp, url_prefix='/github')

OAuth server (provider) on the other hand is a little complex, find a real
:ref:`flask_oauth2_server` via
`Example of OAuth 2.0 server <https://github.com/authlib/example-oauth2-server>`_.

User Guide
----------

This part of the documentation begins with some background information
about Authlib, and installation of Authlib.

.. toctree::
    :maxdepth: 2

    intro
    install
    community/licenses

Client Guide
------------

This part of the documentation contains information on the client parts,
for Requests, Flask and Django.

.. toctree::
    :maxdepth: 2

    client/oauth1
    client/oauth2
    client/mixed
    client/flask
    client/django
    client/api

Server Guide
------------

This part of the documentation contains information on the server parts for
frameworks.

.. toctree::
    :maxdepth: 2

    flask/1/index
    flask/2/index
    django/1/index

Specifications
--------------

Guide on specifications. You don't have to read this section if you are
just using Authlib. But it would be good for you to understand how Authlib
works.

.. toctree::
    :maxdepth: 1

    specs/rfc5849
    specs/rfc6749
    specs/rfc6750
    specs/rfc7009
    specs/rfc7515
    specs/rfc7516
    specs/rfc7517
    specs/rfc7518
    specs/rfc7519
    specs/rfc7523
    specs/rfc7636
    specs/rfc7662
    specs/oidc

Community & Contribution
------------------------

This section aims to make Authlib sustainable, on governance, code commits,
issues and finance.

.. toctree::
    :maxdepth: 2

    community/support
    community/security
    community/contribute
    community/awesome
    community/sustainable
    community/authors

API Reference
-------------

If you are looking for information on a specific function, class or method for
non specifications, this part of the documentation is for you.

.. toctree::
    :maxdepth: 2

    api/server

Get Updates
-----------

Stay tuned with Authlib, here is a history of Authlib changes.

.. toctree::
    :maxdepth: 2

    changelog

Consider to follow `Authlib on Twitter <https://twitter.com/authlib>`_,
and subscribe `Authlib Blog <https://blog.authlib.org/>`_.
