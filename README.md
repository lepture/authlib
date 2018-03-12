<a href="https://authlib.org/"><img src="https://authlib.org/logo.svg" align="right" width="140" /></a>

# Authlib

<a href="https://travis-ci.org/lepture/authlib"><img src="https://api.travis-ci.org/lepture/authlib.svg?branch=master" alt="Build Status"></a>
<a href="https://codecov.io/gh/lepture/authlib?branch=master"><img src="https://codecov.io/gh/lepture/authlib/branch/master/graph/badge.svg" alt="Coverage Status"></a>
<a href="https://pypi.python.org/pypi/authlib/"><img src="https://img.shields.io/pypi/wheel/authlib.svg" alt="Wheel Status"></a>
<a href="https://pypi.python.org/pypi/authlib/"><img src="https://img.shields.io/pypi/v/authlib.svg" alt="PyPI Version"></a>
<a href="https://pypi.python.org/pypi/authlib/"><img src="https://img.shields.io/pypi/status/authlib.svg" alt="Release Stage"></a>
<a href="https://twitter.com/intent/follow?screen_name=authlib"><img src="https://img.shields.io/twitter/follow/authlib.svg?style=social&logo=twitter&label=Follow" alt="Follow Twitter"></a>

Authlib is an ambitious authentication library for OAuth 1, OAuth 2, OpenID
clients, servers and more.

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

## Useful Links

1. Take a look at [Authlib Homepage](https://authlib.org/)
2. Get more information with [Authlib Documentation](https://docs.authlib.org/)
3. Have a taste with [Authlib Playground](https://play.authlib.org/)
4. Stay tuned with [Authlib Newsletter](https://tinyletter.com/authlib)
5. Get latest news via [Authlib on Twitter](https://twitter.com/authlib)
6. Ask questions on StackOverflow with [Authlib Tag](https://stackoverflow.com/questions/tagged/authlib)

## Spec Implementations

Lovely features that Authlib has built-in:

<details>
<summary>🎉 RFC5849: The OAuth 1.0 Protocol</summary>

- [x] OAuth1Session for Requests
- [x] OAuth 1.0 Client for Flask
- [x] OAuth 1.0 Client for Django
- [x] OAuth 1.0 Server for Flask
- [ ] OAuth 1.0 Server for Django
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
<summary>🎉 JSON Web Signature (JWS)</summary>

- [x] "HS256" algorithm via RFC7518
- [x] "HS384" algorithm via RFC7518
- [x] "HS512" algorithm via RFC7518
- [x] "RS256" algorithm via RFC7518
- [x] "RS384" algorithm via RFC7518
- [x] "RS512" algorithm via RFC7518
- [x] "ES256" algorithm via RFC7518
- [x] "ES384" algorithm via RFC7518
- [x] "ES512" algorithm via RFC7518
- [x] "PS256" algorithm via RFC7518
- [x] "PS384" algorithm via RFC7518
- [x] "PS512" algorithm via RFC7518
</details>

<details>
  <summary>⏳ RFC7516: JSON Web Encryption (JWE)</summary>
  <p>JWE implementation is in plan now.</p>
</details>

<details>
<summary>🎉 RFC7517: JSON Web Key (JWK)</summary>

- [x] "oct" algorithm via RFC7518
- [x] "RSA" algorithm via RFC7518
- [x] "EC" algorithm via RFC7518
</details>

<details>
<summary>🎉 JSON Web Algorithms (JWA)</summary>

- [x] Algorithms for JWS
- [ ] Algorithms for JWE
- [x] Algorithms for JWK
</details>

<details>
  <summary>🎉 RFC7519: JSON Web Token (JWT)</summary>
  <p>JWT shares the same interface with JWS. Besides that, JWT has payload claims validation.</p>
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
  <summary>⏳ RFC7523: JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants</summary>
  <p>RFC7523 implementation is in plan.</p>
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
  <summary>⏳ RFC7636: Proof Key for Code Exchange by OAuth Public Clients</summary>
  <p>RFC7636 implementation is in plan.</p>
</details>

<details>
<summary>🎉 RFC7662: OAuth 2.0 Token Introspection</summary>

- [x] Token Introspection for Flask OAuth 2.0 Server
- [ ] Token Introspection for Django OAuth 2.0 Server
</details>

<details>
<summary>🎉 OpenID Connect 1.0</summary>

- [x] OpenID Claims validation
- [x] OpenID Connect for Flask OAuth 2.0 Server
- [ ] OpenID Connect for Django OAuth 2.0 Server
</details>

<details>
  <summary>⏳ OpenID Connect Discovery 1.0</summary>
  <p>Developers can create a JSON file himself.</p>
</details>

And more will be added.

## Framework Integrations

Framework integrations with current specification implementations:

- [x] Requests OAuth 1 Session
- [x] Requests OAuth 2 Session
- [x] Flask OAuth 1/2 Client
- [x] Django OAuth 1/2 Client
- [x] Flask OAuth 1 Server
- [x] Flask OAuth 2 Server
- [x] Flask OpenID Connect Server
- [ ] Django OAuth 1 Server
- [ ] Django OAuth 2 Server
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

Authlib is licensed under LGPLv3. Please see LICENSE for licensing details.

If this license does not fit your company, consider to purchase a commercial
license.

Find more information on <https://authlib.org/support#commercial-license>
