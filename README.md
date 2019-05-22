<a href="https://authlib.org/">
<img align="right" width="120" height="120" src="https://authlib.org/logo.svg">
</a>

# Authlib

<a href="https://lepture.com/donate"><img src="https://badgen.net/badge/donate/lepture/ff69b4" /></a>
<a href="https://travis-ci.com/lepture/authlib"><img src="https://api.travis-ci.com/lepture/authlib.svg?branch=master" alt="Build Status"></a>
<a href="https://codecov.io/gh/lepture/authlib?branch=master"><img src="https://codecov.io/gh/lepture/authlib/branch/master/graph/badge.svg" alt="Coverage Status"></a>
<a href="https://pypi.org/project/Authlib/"><img src="https://badgen.net/pypi/v/authlib" alt="PyPI Version"></a>
<a href="https://pypi.org/project/Authlib/"><img src="https://img.shields.io/pypi/status/authlib.svg?maxAge=3600" alt="Release Stage"></a>
<a href="https://codeclimate.com/github/lepture/authlib/maintainability"><img src="https://api.codeclimate.com/v1/badges/8c09859e1ab803f7b9ac/maintainability" alt="Maintainability" /></a>
<a href="https://twitter.com/intent/follow?screen_name=authlib"><img src="https://img.shields.io/twitter/follow/authlib.svg?maxAge=3600&style=social&logo=twitter&label=Follow" alt="Follow Twitter"></a>

The ultimate Python library in building OAuth and OpenID Connect servers.
JWS, JWK, JWA, JWT are included.

Authlib is compatible with Python2.7+ and Python3.5+.

```python
authorization_server.register_grant(AuthorizationCodeGrant)
authorization_server.register_grant(ImplicitGrant)
authorization_server.register_grant(ResourceOwnerPasswordGrant)
authorization_server.register_grant(ClientCredentialsGrant)
authorization_server.register_grant(RefreshTokenGrant)
authorization_server.register_grant(OpenIDCodeGrant)
authorization_server.register_grant(OpenIDImplicitGrant)
authorization_server.register_grant(OpenIDHybridGrant)
authorization_server.register_endpoint(RevocationEndpoint)
authorization_server.register_endpoint(IntrospectionEndpoint)
```

## Sponsors

<table>
  <tr>
    <td><img align="middle" width="48" src="https://user-images.githubusercontent.com/290496/39297078-89d00928-497d-11e8-8119-0c53afe14cd0.png"></td>
    <td>If you want to quickly add secure token-based authentication to Python projects, feel free to check Auth0's Python SDK and free plan at <a href="https://auth0.com/overview?utm_source=GHsponsor&utm_medium=GHsponsor&utm_campaign=authlib&utm_content=auth">auth0.com/overview</a>.</td>
  </tr>
</table>

[**Become a backer via Patreon**](https://www.patreon.com/lepture).

## Useful Links

1. Homepage: <https://authlib.org/>.
2. Documentation: <https://docs.authlib.org/>.
3. Blog: <https://blog.authlib.org/>.
4. Twitter: <https://twitter.com/authlib>.
5. StackOverflow: <https://stackoverflow.com/questions/tagged/authlib>.
6. Other Repositories: <https://github.com/authlib>.

## Spec Implementations

Lovely features that Authlib has built-in:

<details>
<summary>🎉 RFC5849: The OAuth 1.0 Protocol</summary>

- [x] OAuth1Session for Requests
- [x] OAuth 1.0 Client for Flask
- [x] OAuth 1.0 Client for Django
- [x] OAuth 1.0 Server for Flask
- [x] OAuth 1.0 Server for Django
</details>

<details>
<summary>🎉 RFC6749: The OAuth 2.0 Authorization Framework</summary>

- [x] OAuth2Session for Requests
- [x] OAuth 2.0 Client for Flask
- [x] OAuth 2.0 Client for Django
- [x] OAuth 2.0 Server for Flask
- [ ] OAuth 2.0 Server for Django
</details>

<details>
<summary>🎉 RFC6750: The OAuth 2.0 Authorization Framework: Bearer Token Usage</summary>

- [x] Bearer Token for OAuth2Session
- [x] Bearer Token for Flask OAuth 2.0 Server
- [ ] Bearer Token for Django OAuth 2.0 Server
</details>

<details>
<summary>🎉 RFC7009: OAuth 2.0 Token Revocation</summary>

- [x] Token Revocation for Flask OAuth 2.0 Server
- [ ] Token Revocation for Django OAuth 2.0 Server
</details>

<details>
<summary>🎉 RFC7515: JSON Web Signature (JWS)</summary>

- [x] Compact serialize and deserialize
- [x] JSON serialize and deserialize
</details>

<details>
<summary>🎉 RFC7516: JSON Web Encryption (JWE)</summary>

- [x] Compact serialize and deserialize
- [ ] JSON serialize and deserialize
</details>

<details>
<summary>🎉 RFC7517: JSON Web Key (JWK)</summary>

- [x] "oct" algorithm via RFC7518
- [x] "RSA" algorithm via RFC7518
- [x] "EC" algorithm via RFC7518
</details>

<details>
<summary>🎉 RFC7518: JSON Web Algorithms (JWA)</summary>

- [x] Algorithms for JWS
- [x] Algorithms for JWE (some of them)
- [x] Algorithms for JWK
</details>

<details>
<summary>🎉 RFC7519: JSON Web Token (JWT)</summary>

- [x] Use JWS for JWT
- [x] Use JWE for JWT
- [x] Payload claims validation
</details>

<details>
  <summary>⏳ RFC7521: Assertion Framework for OAuth 2.0 Client Authentication and Authorization Grants</summary>
  <p>RFC7521 implementation is in plan.</p>
</details>

<details>
  <summary>⏳ RFC7522: Security Assertion Markup Language (SAML) 2.0 Profile for OAuth 2.0 Client Authentication and Authorization Grants</summary>
  <p>RFC7522 implementation is in plan.</p>
</details>

<details>
<summary>🎉 RFC7523: JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants</summary>

- [x] Using JWTs as Client Authorization
- [x] Using JWTs as Authorization Grants
</details>

<details>
  <summary>🎁 RFC7591: OAuth 2.0 Dynamic Client Registration Protocol</summary>
  <p>RFC7591 implementation is in plan. However, Flask SQLAlchemy ClientMixin is designed based on it.</p>
</details>

<details>
  <summary>⏳ RFC7592: OAuth 2.0 Dynamic Client Registration Management Protocol</summary>
  <p>RFC7592 implementation is in plan.</p>
</details>

<details>
<summary>🎉  RFC7636: Proof Key for Code Exchange by OAuth Public Clients</summary>

- [x] Flask/Django client integrations
- [x] Server side grant implementation
</details>

<details>
<summary>🎉 RFC7662: OAuth 2.0 Token Introspection</summary>

- [x] Token Introspection for Flask OAuth 2.0 Server
- [ ] Token Introspection for Django OAuth 2.0 Server
</details>

<details>
<summary>⏳ RFC7797: JSON Web Signature (JWS) Unencoded Payload Option</summary>
<p>RFC7797 implementation is in plan.</p>
</details>

<details>
<summary>🎉 RFC8414: OAuth 2.0 Authorization Server Metadata</summary>

- [x] Authorization Server Metadata Model
- [ ] Framework integrations
</details>

<details>
<summary>🎉 OpenID Connect 1.0</summary>

- [x] OpenID Claims validation
- [x] OpenID Connect for Flask OAuth 2.0 Server
- [ ] OpenID Connect for Django OAuth 2.0 Server
</details>

<details>
  <summary>⏳ OpenID Connect Discovery 1.0</summary>
  <p>Developers can create a JSON file themselves.</p>
</details>

And more will be added.

## Framework Integrations

Framework integrations with current specification implementations:

- [x] Requests OAuth 1 Session
- [x] Requests OAuth 2 Session
- [x] Requests Assertion Session
- [x] Flask OAuth 1/2 Client
- [x] Django OAuth 1/2 Client
- [x] Flask OAuth 1.0 Server
- [x] Flask OAuth 2.0 Server
- [x] Flask OpenID Connect 1.0
- [x] Django OAuth 1.0 Server
- [ ] Django OAuth 2.0 Server
- [ ] Django OpenID Connect Server


## Security Reporting

If you found security bugs which can not be public, please send me
email at <me@lepture.com>. Attachment with patch is welcome. My PGP
Key fingerprint is:

```
72F8 E895 A70C EBDF 4F2A DFE0 7E55 E3E0 118B 2B4C
```

You can also find it at <https://keybase.io/lepture>.


## License

Authlib is licensed under BSD. Please see LICENSE for licensing details.

There is also a commercial license which you can purchase at
[Authlib Plans](https://authlib.org/plans) page.

## Support

If you need any help, you can always ask questions on StackOverflow with
a tag of "Authlib". DO NOT ASK HELP IN GITHUB ISSUES.

We also provide commercial consulting and supports. You can find more
information at <https://authlib.org/support>.
