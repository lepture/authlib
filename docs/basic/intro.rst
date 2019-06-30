.. _intro:

Introduction
============

.. meta::
    :description: A general introduction to Authlib, a project that powers from
        low-level specification implementation to high-level framework
        integrations.

Authlib is the ultimate Python library in building OAuth and OpenID Connect
clients and servers. It offers generic implementations of RFCs, including
OAuth 1.0, OAuth 2.0, JWT and many more. It becomes a :ref:`monolithic`
project that powers from low-level specification implementation to high-level
framework integrations.

I'm intended to make it profitable so that it can be :ref:`sustainable`.

.. raw:: html
   :file: ../_templates/tidelift.html

.. _monolithic:

Monolithic
----------

Authlib is a monolithic library. While being monolithic, it keeps everything
synchronized, from spec implementation to framework integrations, from client
requests to service providers.

The benefits are obvious; it won't break things. When specifications changed,
implementation will change too. Let the developers of Authlib take the pain,
users of Authlib should not suffer from it.

You don't have to worry about monolithic, it doesn't cost your memory. If
you don't import a module, it won't be loaded. We don't madly import everything
into the root **__init__.py**.

Flexible
--------

Authlib is designed as flexible as possible. Since it is built from low-level
specification implementation to high-level framework integrations, if a high
level can't meet your needs, you can always create one for your purpose based on
the low-level implementation.

Most of the cases, you don't need to do so. Flexible has been taken
into account from the start of the project. Take OAuth 2.0 server as an
example, instead of a pre-configured server, Authlib takes advantage of
``register``.

.. code-block:: python

    authorization_server.register_grant(AuthorizationCodeGrant)
    authorization_server.register_endpoint(RevocationEndpoint)

If you find anything not that flexible, you can ask help on StackOverflow or
open an issue on GitHub.

Specification
-------------

Authlib is a spec-compliant library which follows the latest specifications.
We keep the generic tool functions in a ``specs`` module. When there is a
auth-related specification, we add it into ``specs``.

Currently, these specs are in the warehouse:

- :badge:`done` :ref:`specs/rfc5849`
- :badge:`done` :ref:`specs/rfc6749`
- :badge:`done` :ref:`specs/rfc6750`
- :badge:`done` :ref:`specs/rfc7009`
- :badge:`done` :ref:`specs/rfc7515`
- :badge-blue:`beta` :ref:`specs/rfc7516`
- :badge:`done` :ref:`specs/rfc7517`
- :badge:`done` :ref:`specs/rfc7518`
- :badge:`done` :ref:`specs/rfc7519`
- :badge:`done` :ref:`specs/rfc7523`
- :badge-blue:`beta` :ref:`specs/rfc7636`
- :badge:`done` :ref:`specs/rfc7662`
- :badge:`done` :ref:`specs/oidc`

Credits
-------

This project is inspired by:

* OAuthLib
* Flask-OAuthlib
* requests-oauthlib
* pyjwt
