.. _client_apps:

Ready to Use Apps
=================

There are built-in configuration for famous services. Import them and register
them to frameworks registry. If you haven't read :ref:`client_frameworks`,
head over back to that section.

.. warning:: This is a preview version, the API will be stable in version 0.2.

Twitter
-------

Register Twitter to the oauth registry::

    from authlib.client.apps import twitter

    twitter.register_to(oauth)

If you are using Flask, you need to configure the consumer key and secret:

========================== =========================
TWITTER_CLIENT_KEY         Twitter Consumer Key
TWITTER_CLIENT_SECRET      Twitter Consumer Secret
========================== =========================

If you are using Django. It's still under construction.

Facebook
--------

Register Facebook to the oauth registry::

    from authlib.client.apps import facebook

    facebook.register_to(oauth)

If you are using Flask, you need to configure your client ID and secret.

========================== ================================
FACEBOOK_CLIENT_KEY        Your Facebook client ID
FACEBOOK_CLIENT_SECRET     Your Facebook client secret
FACEBOOK_CLIENT_KWARGS     Configure scope and other things
========================== ================================

If you are using Django. It's still under construction.

BTW, compliance fix is configured already, no worries.

Google
------

Register Google to the oauth registry::

    from authlib.client.apps import google

    google.register_to(oauth)

If you are using Flask, you need to configure your client ID and secret.

========================== ================================
GOOGLE_CLIENT_KEY          Your Google client ID
GOOGLE_CLIENT_SECRET       Your Google client secret
GOOGLE_CLIENT_KWARGS       Configure scope and other things
========================== ================================

GitHub
------

Register GitHub to the oauth registry::

    from authlib.client.apps import github

    github.register_to(oauth)

If you are using Flask, you need to configure your client ID and secret.

========================== ================================
GITHUB_CLIENT_KEY          Your GitHub client ID
GITHUB_CLIENT_SECRET       Your GitHub client secret
GITHUB_CLIENT_KWARGS       Configure scope and other things
========================== ================================

Dropbox
-------

Register Dropbox to the oauth registry::

    from authlib.client.apps import dropbox

    dropbox.register_to(oauth)

If you are using Flask, you need to configure your client ID and secret.

========================== ================================
DROPBOX_CLIENT_KEY         Your Dropbox client ID
DROPBOX_CLIENT_SECRET      Your Dropbox client secret
DROPBOX_CLIENT_KWARGS      Configure scope and other things
========================== ================================
