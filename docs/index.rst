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


Features
--------

Generic specification implementations that Authlib has built-in:

- :badge:`done` RFC5849: :ref:`specs/rfc5849`
- :badge:`done` RFC6749: :ref:`specs/rfc6749`
- :badge:`done` RFC6750: :ref:`specs/rfc6750`
- :badge:`done` RFC7009: :ref:`specs/rfc7009`
- :badge:`done` RFC7515: :ref:`specs/rfc7515`
- :badge:`doing` RFC7516: JSON Web Encryption
- :badge:`done` RFC7517: :ref:`specs/rfc7517`
- :badge-blue:`part` RFC7518: :ref:`specs/rfc7518`
- :badge:`done` RFC7519: :ref:`specs/rfc7519`
- :badge-blue:`part` RFC7523: :ref:`specs/rfc7523`
- :badge:`done` RFC7662: :ref:`specs/rfc7662`
- :badge:`done` OIDC: :ref:`specs/oidc`

Framework integrations with current specification implementations:

- :badge-green:`ready` Requests :ref:`oauth_1_session`
- :badge-green:`ready` Requests :ref:`oauth_2_session`
- :badge-green:`ready` :ref:`flask_client`
- :badge-green:`ready` :ref:`django_client`
- :badge-green:`ready` :ref:`flask_oauth1_server`
- :badge-green:`ready` :ref:`flask_oauth2_server`
- :badge-blue:`beta` :ref:`flask_odic_server`
- :badge:`todo` Django OAuth 1 Server
- :badge:`todo` Django OAuth 2 Server
- :badge:`todo` Django OpenID Connect Server

Authlib is compatible with Python2.7+ and Python3.5+.

User Guide
----------

This part of the documentation begins with some background information
about Authlib, and installation of Authlib.

.. toctree::
    :maxdepth: 2

    intro
    install

Client Guide
------------

This part of the documentation contains information on the client parts,
for Requests, Flask and Django.

.. toctree::
    :maxdepth: 2

    client/oauth1
    client/oauth2
    client/mixed
    client/frameworks

.. toctree::
    :maxdepth: 1

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
    specs/rfc7517
    specs/rfc7518
    specs/rfc7519
    specs/rfc7523
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
    api/errors

Get Updates
-----------

Stay tuned with Authlib, here is a history of Authlib changes.

.. toctree::
    :maxdepth: 2

    changelog
