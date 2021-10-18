Changelog
=========

.. meta::
    :description: The full list of changes between each Authlib release.

Here you can see the full list of changes between each Authlib release.

Version 0.15.5
--------------

**Released on Oct 18, 2021.**

- Make Authlib compatible with latest httpx
- Make Authlib compatible with latest werkzeug
- Allow customize RFC7523 ``alg`` value


Version 0.15.4
--------------

**Released on Jul 17, 2021.**

- Security fix when JWT claims is None

Version 0.15.3
--------------

**Released on Jan 15, 2021.**

- Fixed fetch OAuth 1.0 token bug, via :gh:`issue#308`.

Version 0.15.2
--------------

**Released on Oct 18, 2020.**

- Fixed HTTPX authentication bug, via :gh:`issue#283`.

Version 0.15.1
--------------

**Released on Oct 14, 2020.**

- Backward compitable fix for using JWKs in JWT, via :gh:`issue#280`.


Version 0.15
------------

**Released on Oct 10, 2020.***

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


Version 0.13
------------

**Released on Nov 11, 2019. Go Async**

This is the release that makes Authlib one more step close to v1.0. We
did a huge refactor on our integrations. Authlib believes in monolithic
design, it enables us to design the API to integrate with every framework
in the best way. In this release, Authlib has re-organized the folder
structure, moving every integration into the ``integrations`` folder. It
makes Authlib to add more integrations easily in the future.

**RFC implementations** and updates in this release:

- RFC7591: OAuth 2.0 Dynamic Client Registration Protocol
- RFC8628: OAuth 2.0 Device Authorization Grant

**New integrations** and changes in this release:

- **HTTPX** OAuth 1.0 and OAuth 2.0 clients in both sync and async way
- **Starlette** OAuth 1.0 and OAuth 2.0 client registry
- The experimental ``authlib.client.aiohttp`` has been removed

**Bug fixes** and enhancements in this release:

- Add custom client authentication methods for framework integrations.
- Refresh token automatically for client_credentials grant type.
- Enhancements on JOSE, specifying ``alg`` values easily for JWS and JWE.
- Add PKCE into requests OAuth2Session and HTTPX OAuth2Client.

**Deprecate Changes**: find how to solve the deprecate issues via https://git.io/Jeclj

Version 0.12
------------

**Released on Sep 3, 2019.**

**Breaking Change**: Authlib Grant system has been redesigned. If you
are creating OpenID Connect providers, please read the new documentation
for OpenID Connect.

**Important Update**: Django OAuth 2.0 server integration is ready now.
You can create OAuth 2.0 provider and OpenID Connect 1.0 with Django
framework.

RFC implementations and updates in this release:

- RFC6749: Fixed scope validation, omit the invalid scope
- RFC7521: Added a common ``AssertionClient`` for the assertion framework
- RFC7662: Added ``IntrospectionToken`` for introspection token endpoint
- OpenID Connect Discover: Added discovery model based on RFC8414

Refactor and bug fixes in this release:

- **Breaking Change**: add ``RefreshTokenGrant.revoke_old_credential`` method
- Rewrite lots of code for ``authlib.client``, no breaking changes
- Refactor ``OAuth2Request``, use explicit query and form
- Change ``requests`` to optional dependency
- Add ``AsyncAssertionClient`` for aiohttp

**Deprecate Changes**: find how to solve the deprecate issues via https://git.io/fjPsV

Version 0.11
------------

**Released on Apr 6, 2019.**

**BIG NEWS**: Authlib has changed its open source license **from AGPL to BSD**.

**Important Changes**: Authlib specs module has been split into jose, oauth1,
oauth2, and oidc. Find how to solve the deprecate issues via https://git.io/fjvpt

RFC implementations and updates in this release:

- RFC7518: Added A128GCMKW, A192GCMKW, A256GCMKW algorithms for JWE.
- RFC5849: Removed draft-eaton-oauth-bodyhash-00 spec for OAuth 1.0.

Small changes and bug fixes in this release:

- Fixed missing scope on password and client_credentials grant types
  of ``OAuth2Session`` via :gh:`issue#96`.
- Fixed Flask OAuth client cache detection via :gh:`issue#98`.
- Enabled ssl certificates for ``OAuth2Session`` via :gh:`PR#100`, thanks
  to pingz.
- Fixed error response for invalid/expired refresh token via :gh:`issue#112`.
- Fixed error handle for invalid redirect uri via :gh:`issue#113`.
- Fixed error response redirect to fragment via :gh:`issue#114`.
- Fixed non-compliant responses from RFC7009 via :gh:`issue#119`.

**Experiment Features**: There is an experiment ``aiohttp`` client for OAuth1
and OAuth2 in ``authlib.client.aiohttp``.


Old Versions
------------

Find old changelog at https://github.com/lepture/authlib/releases

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
