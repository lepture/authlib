.. _django_oauth1_server:

Django OAuth 1.0 Server
=======================

.. meta::
    :description: How to create an OAuth 1.0 server in Django with Authlib.
        And understand how OAuth 1.0 works.

This is just an alpha implementation of Django OAuth 1.0 provider. An OAuth 1
provider contains two servers:

- Authorization Server: to issue access tokens
- Resources Server: to serve your users' resources

.. important::

    If you are developing on your localhost, remember to set the environment
    variable::

        export AUTHLIB_INSECURE_TRANSPORT=true

Here are the details in documentation:

.. toctree::
    :maxdepth: 2

    authorization-server
    resource-server
    api
