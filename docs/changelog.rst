Changelog
=========

.. meta::
    :description: The full list of changes between each Authlib release.

Here you can see the full list of changes between each Authlib release.

Version x.x.x
-------------

- Fixed RFC7591 and RFC7592 ``grant_types`` and ``response_types`` default values, via :gh:`PR#509`.

Version 1.2.0
-------------

**Released on Dec 6, 2022**

- Not passing ``request.body`` to ``ResourceProtector``, via :gh:`issue#485`.
- Use ``flask.g`` instead of ``_app_ctx_stack``, via :gh:`issue#482`.
- Add ``headers`` parameter back to ``ClientSecretJWT``, via :gh:`issue#457`.
- Always passing ``realm`` parameter in OAuth 1 clients, via :gh:`issue#339`.
- Implemented RFC7592 Dynamic Client Registration Management Protocol, via :gh:`PR#505`.
- Add ``default_timeout`` for requests ``OAuth2Session`` and ``AssertionSession``.
- Deprecate ``jwk.loads`` and ``jwk.dumps``

Version 1.1.0
-------------

**Released on Sep 13, 2022**

This release contains breaking changes and security fixes.

- Allow to pass ``claims_options`` to Framework OpenID Connect clients, via :gh:`PR#446`.
- Fix ``.stream`` with context for HTTPX OAuth clients, via :gh:`PR#465`.
- Fix Starlette OAuth client for cache store, via :gh:`PR#478`.

**Breaking changes**:

- Raise ``InvalidGrantError`` for invalid code, redirect_uri and no user errors in OAuth
  2.0 server.
- The default ``authlib.jose.jwt`` would only work with JSON Web Signature algorithms, if
  you would like to use JWT with JWE algorithms, please pass the algorithms parameter::

      jwt = JsonWebToken(['A128KW', 'A128GCM', 'DEF'])

**Security fixes**: CVE-2022-39175 and CVE-2022-39174, both related to JOSE.

Version 1.0.1
-------------

**Released on Apr 6, 2022**

- Fix authenticate_none method, via :gh:`issue#438`.
- Allow to pass in alternative signing algorithm to RFC7523 authentication methods via :gh:`PR#447`.
- Fix ``missing_token`` for Flask OAuth client, via :gh:`issue#448`.
- Allow ``openid`` in any place of the scope, via :gh:`issue#449`.
- Security fix for validating essential value on blank value in JWT, via :gh:`issue#445`.


Version 1.0.0
-------------

**Released on Mar 15, 2022.**

We have dropped support for Python 2 in this release. We have removed
built-in SQLAlchemy integration.

**OAuth Client Changes:**

The whole framework client integrations have been restructured, if you are
using the client properly, e.g. ``oauth.register(...)``, it would work as
before.

**OAuth Provider Changes:**

In Flask OAuth 2.0 provider, we have removed the deprecated
``OAUTH2_JWT_XXX`` configuration, instead, developers should define
`.get_jwt_config` on OpenID extensions and grant types.

**SQLAlchemy** integrations has been removed from Authlib. Developers
should define the database by themselves.

**JOSE Changes**

- ``JWS`` has been renamed to ``JsonWebSignature``
- ``JWE`` has been renamed to ``JsonWebEncryption``
- ``JWK`` has been renamed to ``JsonWebKey``
- ``JWT`` has been renamed to ``JsonWebToken``

The "Key" model has been re-designed, checkout the :ref:`jwk_guide` for updates.

Added ``ES256K`` algorithm for JWS and JWT.

**Breaking Changes**: find how to solve the deprecate issues via https://git.io/JkY4f


Version 0.15.5
--------------

**Released on Oct 18, 2021.**

- Make Authlib compatible with latest httpx
- Make Authlib compatible with latest werkzeug
- Allow customize RFC7523 ``alg`` value

Version 0.15.4
--------------

**Released on Jul 17, 2021.**

- Security fix when JWT claims is None.


Version 0.15.3
--------------

**Released on Jan 15, 2021.**

- Fixed `.authorize_access_token` for OAuth 1.0 services, via :gh:`issue#308`.

Version 0.15.2
--------------

**Released on Oct 18, 2020.**

- Fixed HTTPX authentication bug, via :gh:`issue#283`.


Version 0.15.1
--------------

**Released on Oct 14, 2020.**

- Backward compatible fix for using JWKs in JWT, via :gh:`issue#280`.


Version 0.15
------------

**Released on Oct 10, 2020.**

This is the last release before v1.0. In this release, we added more RFCs
implementations and did some refactors for JOSE:

- RFC8037: CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JSON Object Signing and Encryption (JOSE)
- RFC7638: JSON Web Key (JWK) Thumbprint

We also fixed bugs for integrations:

- Fixed support for HTTPX>=0.14.3
- Added OAuth clients of HTTPX back via :gh:`PR#270`
- Fixed parallel token refreshes for HTTPX async OAuth 2 client
- Raise OAuthError when callback contains errors via :gh:`issue#275`

**Breaking Change**:

1. The parameter ``algorithms`` in ``JsonWebSignature`` and ``JsonWebEncryption``
are changed. Usually you don't have to care about it since you won't use it directly.
2. Whole JSON Web Key is refactored, please check :ref:`jwk_guide`.

Version 0.14.3
--------------

**Released on May 18, 2020.**

- Fix HTTPX integration via :gh:`PR#232` and :gh:`PR#233`.
- Add "bearer" as default token type for OAuth 2 Client.
- JWS and JWE don't validate private headers by default.
- Remove ``none`` auth method for authorization code by default.
- Allow usage of user provided ``code_verifier`` via :gh:`issue#216`.
- Add ``introspect_token`` method on OAuth 2 Client via :gh:`issue#224`.


Version 0.14.2
--------------

**Released on May 6, 2020.**

- Fix OAuth 1.0 client for starlette.
- Allow leeway option in client parse ID token via :gh:`PR#228`.
- Fix OAuthToken when ``expires_at`` or ``expires_in`` is 0 via :gh:`PR#227`.
- Fix auto refresh token logic.
- Load server metadata before request.


Version 0.14.1
--------------

**Released on Feb 12, 2020.**

- Quick fix for legacy imports of Flask and Django clients


Version 0.14
------------

**Released on Feb 11, 2020.**

In this release, Authlib has introduced a new way to write framework integrations
for clients.

**Bug fixes** and enhancements in this release:

- Fix HTTPX integrations due to HTTPX breaking changes
- Fix ES algorithms for JWS
- Allow user given ``nonce`` via :gh:`issue#180`.
- Fix OAuth errors ``get_headers`` leak.
- Fix ``code_verifier`` via :gh:`issue#165`.

**Breaking Change**: drop sync OAuth clients of HTTPX.


Old Versions
------------

Find old changelog at https://github.com/lepture/authlib/releases

- Version 0.13.0: Released on Nov 11, 2019
- Version 0.12.0: Released on Sep 3, 2019
- Version 0.11.0: Released on Apr 6, 2019
- Version 0.10.0: Released on Oct 12, 2018
- Version 0.9.0: Released on Aug 12, 2018
- Version 0.8.0: Released on Jun 17, 2018
- Version 0.7.0: Released on Apr 28, 2018
- Version 0.6.0: Released on Mar 20, 2018
- Version 0.5.1: Released on Feb 11, 2018
- Version 0.5.0: Released on Feb 11, 2018
- Version 0.4.1: Released on Feb 2, 2018
- Version 0.4.0: Released on Jan 31, 2018
- Version 0.3.0: Released on Dec 24, 2017
- Version 0.2.1: Released on Dec 6, 2017
- Version 0.2.0: Released on Nov 25, 2017
- Version 0.1.0: Released on Nov 18, 2017
