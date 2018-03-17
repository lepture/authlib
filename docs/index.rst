.. Authlib documentation master file, created by
   sphinx-quickstart on Wed Nov  1 11:04:52 2017.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Authlib: Python Authentication
==============================

Release v\ |version|. (:ref:`Installation <install>`)

Authlib is an ambitious authentication library for OAuth 1, OAuth 2, OpenID
clients and servers. It is designed from low level APIs to high level APIs,
to meet the needs of everyone.


Features
--------

Generic specification implementations that Authlib has built-in:

- RFC5849: :ref:`specs/rfc5849`
- RFC6749: :ref:`specs/rfc6749`
- RFC6750: :ref:`specs/rfc6750`
- RFC7009: :ref:`specs/rfc7009`
- RFC7515: :ref:`specs/rfc7515`
- RFC7517: :ref:`specs/rfc7517`
- RFC7518: :ref:`specs/rfc7518`
- RFC7519: :ref:`specs/rfc7519`
- RFC7662: :ref:`specs/rfc7662`
- OIDC: :ref:`specs/oidc`

Framework integrations with current specification implementations:

- Requests :ref:`oauth_1_session`
- Requests :ref:`oauth_2_session`
- :ref:`flask_client`
- :ref:`django_client`
- :ref:`flask_oauth1_server`
- :ref:`flask_oauth2_server`
- :ref:`flask_odic_server`
- **TODO** Django OAuth 1 Server
- **TODO** Django OAuth 2 Server

Authlib is compatible with Python2.7+ and Python3.5+.

User Guide
----------

This part of the documentation begins with some background information
about Authlib, and information on the client parts.

.. toctree::
    :maxdepth: 2

    intro
    install
    client/oauth1
    client/oauth2
    client/mixed
    client/frameworks
    client/apps

Server Guide
------------

This part of the documentation contains information on the server parts for
frameworks.

.. toctree::
    :maxdepth: 2

    flask/oauth1
    flask/oauth2
    flask/oidc

.. note:: Django support will be added in Version 0.8.

Specifications
--------------

Guide on specifications. You don't have to read this section if you are
just using Authlib. But it would be good for you to understand how Authlib
works.

.. toctree::
    :maxdepth: 2

    specs/rfc5849
    specs/rfc6749
    specs/rfc6750
    specs/rfc7009
    specs/rfc7515
    specs/rfc7517
    specs/rfc7518
    specs/rfc7519
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

    api/client
    api/server

Get Updates
-----------

Stay tuned with Authlib, here is a history of Authlib changes.

.. toctree::
    :maxdepth: 2

    changelog
