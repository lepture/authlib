Changelog
=========

.. meta::
    :description: The full list of changes between each Authlib release.

Here you can see the full list of changes between each Authlib release.

Version 0.11
------------

**Release Date not decided yet.**

**BIG NEWS**: Authlib has changed its open source license from AGPL to BSD.

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

**Deprecate Changes**: find how to solve the deprecate issues via https://git.io/fjvpt

Version 0.10: Kluke
-------------------

**Released on Oct 12, 2018.**

The most important change in this version is grant extension system. When
registering a grant, developers can pass extensions to the grant::

    authorization_server.register_grant(GrantClass, [extension])

Find Flask :ref:`flask_oauth2_grant_extensions` implementation.

RFC implementations and updates in this release:

- RFC8414: OAuth 2.0 Authorization Server Metadata
- RFC7636: make CodeChallenge a grant extension :ref:`specs/rfc7636`
- OIDC: make OpenIDCode a grant extension

Besides that, there are other improvements:

- Export ``save_authorize_state`` method on Flask and Django client
- Add ``fetch_token`` to Django OAuth client
- Add scope operator for ``@require_oauth`` :ref:`flask_oauth2_multiple_scopes`
- Fix two OAuth clients in the same Flask route :gh:`PR#85`

**Deprecate Changes**: find how to solve the deprecate issues via https://git.io/fAmW1

Version 0.9: Ponyo
------------------

**Released on Aug 12, 2018. Fun Dive.**

There is no big break changes in this version. The very great improvement is
adding JWE support. But the JWA parts of JWE are not finished yet, use with
caution.

RFC implementations in this release:

- RFC7636: client and server implementation of :ref:`specs/rfc7636`.
- RFC7523: easy integration of :ref:`jwt_oauth2session`.
- RFC7516: JWE compact serialization and deserialization.
- RFC7519: JWT with JWE encode and decode.

**Other Changes**:

- Fixed the lazy initialization of Flask OAuth 2.0 provider.
- Deprecated ``authlib.client.apps`` from v0.7 has been dropped.


Version 0.8: Arutoria
---------------------

**Released on Jun 17, 2018. Try Django.**

Authlib has tried to introduce Django OAuth server implementation in this
version. It turns out that it is not that easy. In this version, only Django
OAuth 1.0 server is provided.

As always, there are also RFC features added in this release, here is what's
in version 0.8:

- RFC7523: Add JWTs for Client Authentication of :ref:`specs/rfc7523`.
- OIDC: Add ``response_mode=form_post`` support for OpenID Connect.

**Improvement** in this release:

- A new redesigned error system. All errors are subclasses of a ``AuthlibBaseError``.
- I18N support for error descriptions.
- Separate AuthorizationCodeMixin in ``authlib.flask.oauth2.sqla`` via :gh:`issue#57`.
- Add context information when generate token via :gh:`issue#58`.
- Improve JWT key handles, auto load JWK and JWK set.
- Add ``require_oauth.acquire`` with statement, get example on :ref:`flask_oauth2_server`.

**Deprecate Changes**: find how to solve the deprecate issues via https://git.io/vhL75

- Rename config key ``OAUTH2_EXPIRES_IN`` to ``OAUTH2_TOKEN_EXPIRES_IN``.
- Rename Flask OAuth 2.0 ``create_expires_generator`` to
  ``create_token_expires_in_generator``

Version 0.7: Honami
-------------------

**Released on Apr 28, 2018. Better Beta.**

Authlib has changed its license from LGPL to AGPL. This is not a huge release
like v0.6, but it still contains some deprecate changes, the good news is
they are compatible, they won't break your project. Authlib can't go further
without these deprecate changes.

As always, Authlib is adding specification implementations. Here is what's in
version 0.7:

- RFC7515_: Refactored :class:`~authlib.rfc7515.JWS`, make it a full implementation.
- RFC7521_: Add :class:`~authlib.client.AssertionSession`, only works with RFC7523_.
- RFC7523_: Add :class:`~authlib.oauth2.rfc7523.JWTBearerGrant`, read the guide in
  :ref:`specs/rfc7523`.

Besides that, there are more changes:

- Add ``overwrite`` parameter for framework integrations clients.
- Add ``response_mode=query`` for OpenID Connect implicit and hybrid flow.
- Bug fix and documentation fix via :gh:`issue#42`, :gh:`issue#43`.
- Dropping ``authlib.client.apps``. Use Loginpass_ instead.

**Deprecate Changes**: find how to solve the deprecate issues via https://git.io/vpCH5

.. _RFC7521: https://tools.ietf.org/html/rfc7521
.. _RFC7523: https://tools.ietf.org/html/rfc7523
.. _Loginpass: https://github.com/authlib/loginpass


Version 0.6: Matoi
------------------

**Released on Mar 20, 2018. Going Beta!**

From alpha to beta. This is a huge release with lots of deprecating changes
and some breaking changes. And finally, OpenID Connect server is supported
by now, because Authlib has added these specifications:

- RFC7515_: JSON Web Signature (JWS)
- RFC7517_: JSON Web Key (JWK)
- RFC7518_: JSON Web Algorithms (JWA)
- RFC7519_: JSON Web Token (JWT)

The specifications are not completed yet, but they are ready to use. The
missing RFC7516 (JWE) is going to be implemented in next version. Open ID
Connect 1.0 is added with:

- Authentication using the :ref:`flask_odic_code`
- Authentication using the :ref:`flask_odic_implicit`
- Authentication using the :ref:`flask_odic_hybrid`
- ID Token Validation

Besides that, there are more changes:

- Implementation of RFC7662: OAuth 2.0 Token Introspection via :gh:`PR#36`.
- Use the ``token_endpoint_auth_method`` concept defined in `RFC7591`_.
- Signal feature for Flask integration of OAuth 2.0 server.
- Bug fixes for OAuth client parts, thanks for the instruction by Lukas Schink.

**Breaking Changes**:

1. the columns in ``authlib.flask.oauth2.sqla`` has been changed a lot.
   If you are using it, you need to upgrade your database.

2. use ``register_token_validator`` on
   :ref:`ResourceProtector <flask_oauth2_resource_protector>`.

3. ``authlib.client.oauth1.OAuth1`` has been renamed to
   ``authlib.client.oauth1.OAuth1Auth``.

**Deprecate Changes**: find how to solve the deprecate issues via https://git.io/vAAUK

.. _`RFC7515`: https://tools.ietf.org/html/rfc7515
.. _`RFC7517`: https://tools.ietf.org/html/rfc7517
.. _`RFC7518`: https://tools.ietf.org/html/rfc7518
.. _`RFC7519`: https://tools.ietf.org/html/rfc7519
.. _`RFC7591`: https://tools.ietf.org/html/rfc7591


Version 0.5.1
-------------

**Released on Feb 11, 2018.**

Just a quick bug fix release.

- Fixed ``OAuth2Session.request`` with auth.


Version 0.5: Kirie
------------------

**Released on Feb 11, 2018. Breaking Changes!**

This version breaks a lot of things. There are many redesigns in order to
get a better stable API. It is still in Alpha stage, with these breaking
changes, I hope Authlib will go into Beta in the next version.

- Added :meth:`~authlib.oauth2.rfc6749.register_error_uri` and its Flask
  integration.
- :class:`~authlib.client.OAuth2Session` supports more grant types.
- Deprecate built-in cache. Read more on :gh:`issue#23`.
- **Redesigned OAuth 1 Flask server**. Read the docs :ref:`flask_oauth1_server`.
- Deprecate ``client_model``. Read more on :gh:`issue#27`.
- **Breaking change** on ``AuthorizationCodeGrant.create_authorization_code``,
  last parameter is changed to an `OAuth2Request` instance.
- Rename ``callback_uri`` to ``redirect_uri`` in client.

Version 0.4.1
-------------

**Released on Feb 2, 2018. A Quick Bugfix**

- Fixed missing code params when fetching access token. This bug is
  introduced when fixing :gh:`issue#16`.

Version 0.4: Tsukino
--------------------

**Released on Jan 31, 2018. Enjoy the Super Blue Blood Moon!**

This is a feature releasing for OAuth 1 server. Things are not settled yet,
there will still be breaking changes in the future. Some of the breaking
changes are compatible with deprecated messages, a few are not. I'll keep the
deprecated message for 2 versions. Here is the main features:

- :ref:`RFC5847 <specs/rfc5849>`, OAuth 1 client and server
- :ref:`Flask implementation <flask_oauth1_server>` of OAuth 1 authorization
  server and resource protector.
- Mixin of SQLAlchemy models for easy integration with OAuth 1.

In version 0.4, there is also several bug fixes. Thanks for the early
contributors.

- Allow Flask OAuth register ``fetch_token`` and ``update_token``.
- Bug fix for OAuthClient when ``refresh_token_params`` is None via :gh:`PR#14`.
- Don't pass everything in request args for Flask OAuth client via :gh:`issue#16`.
- Bug fix for ``IDToken.validate_exp`` via :gh:`issue#17`.

.. admonition:: Deprecated Changes

    There are parameters naming changes in the client part:

    * ``client_key`` has been changed to ``client_id``
    * ``resource_owner_key`` has been changed to ``token``
    * ``resource_owner_secret`` has been changed to ``token_secret``

    Currently, they are backward compatible. You will be notified by warnings.

Version 0.3: Nagato
-------------------

**Released on Dec 24, 2017. Merry Christmas!**

This is a feature releasing for OAuth 2 server. Since this is the first
release of the server implementation, you would expect that there are bugs,
security vulnerabilities, and uncertainties. Try it bravely.

- :ref:`RFC6749 <specs/rfc6749>`, all grant types, refresh token, authorization server.
- :ref:`RFC6750 <specs/rfc6750>`, bearer token creation and validation.
- :ref:`RFC7009 <specs/rfc7009>`, token revocation.
- :ref:`Flask implementation <flask_oauth2_server>` of authorization server and resource protector.
- Mixin of SQLAlchemy models for easy integration with OAuth 2.

Old Versions
------------

- Version 0.2.1: Released on Dec 6, 2017
- Version 0.2: Released on Nov 25, 2017
- Version 0.1: Released on Nov 18, 2017
