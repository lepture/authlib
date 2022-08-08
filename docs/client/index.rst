OAuth Clients
=============

.. meta::
    :description: This documentation contains Python OAuth 1.0 and OAuth 2.0 Clients
        implementation with requests, HTTPX, Flask, Django and Starlette.

This part of the documentation contains information on the client parts. Authlib
provides many frameworks integrations, including:

* The famous Python Requests_
* A next generation HTTP client for Python: httpx_
* Flask_ web framework integration
* Django_ web framework integration
* Starlette_ web framework integration
* FastAPI_ web framework integration

In order to use Authlib client, you have to install each library yourself. For
example, you want to use ``requests`` OAuth clients::

    $ pip install Authlib requests

For instance, you want to use ``httpx`` OAuth clients::

    $ pip install -U Authlib httpx

Here is a simple overview of Flask OAuth client::

    from flask import Flask, jsonify
    from authlib.integrations.flask_client import OAuth

    app = Flask(__name__)
    oauth = OAuth(app)
    github = oauth.register('github', {...})

    @app.route('/login')
    def login():
        redirect_uri = url_for('authorize', _external=True)
        return github.authorize_redirect(redirect_uri)

    @app.route('/authorize')
    def authorize():
        token = github.authorize_access_token()
        # you can save the token into database
        profile = github.get('/user', token=token)
        return jsonify(profile)

Follow the documentation below to find out more in detail.

.. toctree::
    :maxdepth: 2

    oauth1
    oauth2
    requests
    httpx
    frameworks
    flask
    django
    starlette
    fastapi
    api

.. _Requests: https://requests.readthedocs.io/en/master/
.. _httpx: https://www.encode.io/httpx/
.. _Flask: https://flask.palletsprojects.com
.. _Django: https://djangoproject.com
.. _Starlette: https://www.starlette.io
.. _FastAPI: https://fastapi.tiangolo.com/
