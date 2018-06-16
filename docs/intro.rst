.. _intro:

Introduction
============

.. meta::
    :description: A general introduction on Authlib, a project that powers from
        low-level specification implementation to high-level framework
        integrations.

Authlib is a ready to use library for authentication. It was designed to be a
replacement of my Flask-OAuthlib project. Later it becomes a :ref:`monolithic`
project that powers from low-level specification implementation to high-level
framework integrations.

I'm intended to make it profitable, so that it can be :ref:`sustainable`.

.. _monolithic:

Monolithic
----------

Authlib is a monolithic library. While being monolithic, it keeps everything
synchronized, from spec implementation to framework integrations, from client
requests to server providers.

The benefits are obvious, it won't break things. When specifications changed,
implementation will change too. Let the developers of Authlib take the pain,
users of Authlib should not suffer from it.

You don't have to worry about monolithic, it doesn't cost your memory. If
you don't import a module, it won't be loaded. We don't madly import everything
into the root **__init__.py**.

Flexible
--------

Authlib is designed as flexible as possible. Since it is build from low-level
specification implementation to high-level framework integrations, if a high
level can't meet your needs, you can always create one for your own based on
the low level implementation.

Most of the cases, you don't need to do such thing. Flexible has been taken
into account from the start of the project. Take OAuth 2.0 server as an
example, instead of a pre configured server, Authlib takes the advantage of
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
related specification, we add it into ``specs``.

Currently, these specs are in the warehouse:

* RFC5849 :ref:`specs/rfc5849`
* RFC6749 :ref:`specs/rfc6749`
* RFC6750 :ref:`specs/rfc6750`
* RFC7009 :ref:`specs/rfc7009`
* RFC7515 :ref:`specs/rfc7515`
* RFC7517 :ref:`specs/rfc7517`
* RFC7518 :ref:`specs/rfc7518`
* RFC7519 :ref:`specs/rfc7519`
* RFC7662 :ref:`specs/rfc7662`
* OIDC :ref:`specs/oidc`

Credits
-------

This project is inspired by:

* OAuthLib
* Flask-OAuthlib
* requests-oauthlib
* pyjwt
