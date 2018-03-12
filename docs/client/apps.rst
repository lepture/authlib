.. _client_apps:

Ready to Use Apps
=================

.. meta::
   :description: The built-in ready to use famous services, including
      Twitter, Facebook, Google, GitHub, Dropbox, and etc.

There are built-in configuration for famous services. Import them and register
them to frameworks registry. If you haven't read :ref:`client_frameworks`,
head over back to that section.

.. admonition:: Caution

   There is a plan to make "apps" a separated project which will include 100+
   services.

Twitter
-------

Register Twitter to the oauth registry::

    from authlib.client.apps import twitter

    twitter.register_to(oauth)

If you are using Flask, you need to configure the consumer key and secret:

========================== =========================
TWITTER_CLIENT_ID          Twitter Consumer Key
TWITTER_CLIENT_SECRET      Twitter Consumer Secret
========================== =========================

If you are using Django, you need to configure consumer key and secret in
settings::

    AUTHLIB_OAUTH_CLIENTS = {
        'twitter': {
            'client_id': 'Twitter Consumer Key',
            'client_secret': 'Twitter Consumer Secret',
        }
    }

You are use the ``twitter`` instance directly, or access it from ``oauth``
registry::

    twitter.authorize_redirect(redirect_uri)  # Flask
    twitter.authorize_redirect(request, redirect_uri)  # Django

There is a built-in ``profile`` in every app, you can get the user info
with a simple function invoke::

    user = twitter.profile()
    # user contains: id, name, email, data

Facebook
--------

Register Facebook to the oauth registry::

    from authlib.client.apps import facebook

    facebook.register_to(oauth)

If you are using Flask, you need to configure your client ID and secret.

========================== ================================
FACEBOOK_CLIENT_ID         Your Facebook client ID
FACEBOOK_CLIENT_SECRET     Your Facebook client secret
FACEBOOK_CLIENT_KWARGS     Configure scope and other things
========================== ================================

The default scope in ``FACEBOOK_CLIENT_KWARGS`` is ``email public_profile``.

For Django registry, configure client ID and secret in settings::

    AUTHLIB_OAUTH_CLIENTS = {
        'facebook': {
            'client_id': 'Facebook Client ID',
            'client_secret': 'Facebook Client Secret',
            'client_kwargs': {'scope': 'Redefine scope here'},
        }
    }

It has a built-in ``profile`` method too.

Google
------

Register Google to the oauth registry::

    from authlib.client.apps import google

    google.register_to(oauth)

If you are using Flask, you need to configure your client ID and secret.

========================== ================================
GOOGLE_CLIENT_ID           Your Google client ID
GOOGLE_CLIENT_SECRET       Your Google client secret
GOOGLE_CLIENT_KWARGS       Configure scope and other things
========================== ================================

The default scope in ``GOOGLE_CLIENT_KWARGS`` is ``openid email profile``.
Although there is a ``profile`` method with Google app, you don't have
to use it, since Google supports OpenID Connect::

    >>> token = google.authorize_access_token()
    >>> user = google.parse_openid(token)

GitHub
------

Register GitHub to the oauth registry::

    from authlib.client.apps import github

    github.register_to(oauth)

If you are using Flask, you need to configure your client ID and secret.

========================== ================================
GITHUB_CLIENT_ID           Your GitHub client ID
GITHUB_CLIENT_SECRET       Your GitHub client secret
GITHUB_CLIENT_KWARGS       Configure scope and other things
========================== ================================

The default scope in ``GITHUB_CLIENT_KWARGS`` is ``user:email``.

For Django registry, configure client ID and secret in settings::

    AUTHLIB_OAUTH_CLIENTS = {
        'github': {
            'client_id': 'GitHub Client ID',
            'client_secret': 'GitHub Client Secret',
            'client_kwargs': {'scope': 'Redefine scope here'},
        }
    }

It has a built-in ``profile`` method too.

Dropbox
-------

Register Dropbox to the oauth registry::

    from authlib.client.apps import dropbox

    dropbox.register_to(oauth)

If you are using Flask, you need to configure your client ID and secret.

========================== ================================
DROPBOX_CLIENT_ID          Your Dropbox client ID
DROPBOX_CLIENT_SECRET      Your Dropbox client secret
DROPBOX_CLIENT_KWARGS      Configure scope and other things
========================== ================================

There is no default scope for Dropbox.

For Django registry, configure client ID and secret in settings::

    AUTHLIB_OAUTH_CLIENTS = {
        'dropbox': {
            'client_id': 'Dropbox Client ID',
            'client_secret': 'Dropbox Client Secret',
            'client_kwargs': {'scope': 'Redefine scope here'},
        }
    }

It has a built-in ``profile`` method too.


Shortcuts
---------

There are shortcuts for register apps into oauth. It is called ``register_apps``,
with this function, one can register many services at one time::

   from authlib.client.apps import register_apps

   register_apps(oauth, ['twitter', 'google', 'github', 'facebook'])
