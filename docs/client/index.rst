Client Guide
============

This part of the documentation contains information on the client parts. For
``Requests.Session``, Flask integration and Django integration.

In order to use Authlib client, you have to install ``requests`` yourself.
You can either install requests with::

    $ pip install requests

Or you can install with::

    $ pip install Authlib[client]

Here is a simple overview of Flask OAuth client::

    from flask import Flask, jsonify
    from authlib.flask.client import OAuth

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
        profile = github.get('/user')
        return jsonify(profile)

Follow the documentation below to find out more in detail.

.. toctree::
    :maxdepth: 2

    oauth1
    oauth2
    flask
    django
    aiohttp
    mixed
    api
