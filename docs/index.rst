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

A simple :ref:`flask_client` which connects to the GitHub OAuth2 API::

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

    basic/index
    client/index
    jose/index
    flask/1/index
    flask/2/index
    django/1/index
    django/2/index
    specs/index
    community/index


Get Updates
-----------

Stay tuned with Authlib, here is a history of Authlib changes.

.. toctree::
    :maxdepth: 2

    changelog

Consider to follow `Authlib on Twitter <https://twitter.com/authlib>`_,
and subscribe `Authlib Blog <https://blog.authlib.org/>`_.
