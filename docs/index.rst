.. Authlib documentation master file, created by
   sphinx-quickstart on Wed Nov  1 11:04:52 2017.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Authlib: Ready to use Authentication
====================================

Release v\ |version|. (:ref:`Installation <install>`)

Authlib is a ready to use authentication library. It is designed from low level
APIs to high level APIs, to meet the needs of everyone.


Features
--------

Generic specification implementations that Authlib has built-in:

- RFC5849: The OAuth 1.0 Protocol
- RFC6749: The OAuth 2.0 Authorization Framework
- RFC6750: The OAuth 2.0 Authorization Framework: Bearer Token Usage
- RFC7009: OAuth 2.0 Token Revocation
- **TODO** RFC7662: OAuth 2.0 Token Introspection
- OpenID Connect 1.0 (Client is supported)

Framework integrations with current specification implementations:

- Requests OAuth 1 Session
- Requests OAuth 2 Session
- Flask OAuth 1/2 Client
- Django OAuth 1/2 Client
- Flask OAuth 1 Server
- Flask OAuth 2 Server
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

This part of the documentation contains information on the server parts.

.. toctree::
   :maxdepth: 2

   flask/oauth1
   flask/oauth2

.. note:: Django support will be added later.

Specifications
--------------

Guide on specifications. You don't have to read this section if you are
just using Authlib. But it would be good for you to understand how Authlib
works.

(Under Construction)

.. toctree::
   :maxdepth: 2

   spec/rfc5849
   spec/rfc6749
   spec/rfc6750
   spec/rfc7009
   spec/rfc7662
   spec/oidc

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

If you are looking for information on a specific function, class or method,
this part of the documentation is for you.

.. toctree::
   :maxdepth: 2

   api/client
   api/server
   api/misc

Get Updates
-----------

Stay tuned with Authlib, here is a history of Authlib changes.

.. toctree::
   :maxdepth: 2

   changelog

- Subscribe the Newsletter: https://tinyletter.com/authlib
- Follow Authlib on Twitter: https://twitter.com/authlib
