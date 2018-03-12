<a href="https://authlib.org/">
<svg width="120" height="120" xmlns="http://www.w3.org/2000/svg"><g transform="translate(10 15)" fill="none" fill-rule="evenodd"><path d="M80.393 20.76c1.676-8.444.74-14.852-3.223-17.398-1.32-.85-2.904-1.22-4.685-1.154-9.623.362-25.148 13.475-37.833 32.808-15.035 22.913-20.377 45.877-11.925 51.309 4.011 2.579 10.404.75 17.627-4.343" stroke="#3E7FCB" stroke-width="5" stroke-linecap="round"/><path d="M88.104 58.229c7.135-2.74 11.523-6.49 11.751-10.797.528-9.96-21.374-19.182-48.94-20.612a138.292 138.292 0 0 0-7.61-.196C19.274 26.704.52 33.228.041 42.254c-.228 4.299 3.729 8.467 10.512 11.926" stroke="#3E7FCB" stroke-width="5" stroke-linecap="round"/><path d="M43.13 5.914C38.249 1.904 33.67-.25 29.99.024a7.152 7.152 0 0 0-2.726.737c-8.98 4.528-6.111 27.947 6.42 52.29 12.533 24.343 29.97 40.403 38.95 35.875 8.634-4.355 6.304-26.177-5.033-49.493" stroke="#3E7FCB" stroke-width="5" stroke-linecap="round"/><path d="M60 54.468c0 1.005-.896 1.597-1.822 1.597-.687 0-1.404-.326-1.703-1.094-.359-.857-1.135-3.222-2.061-5.972-.06-.177-.15-.266-.33-.266-.477-.03-1.702-.03-3.046-.03-1.793 0-3.794 0-4.422.03a.375.375 0 0 0-.358.266c-.747 2.336-1.434 4.464-1.882 5.883-.27.828-.956 1.212-1.673 1.212-.837 0-1.703-.561-1.703-1.478 0-.532.09-.769 6.632-18.979.478-1.36 1.554-1.98 2.629-1.98 1.135 0 2.3.709 2.778 2.04 1.912 5.32 5.796 15.608 6.782 17.914.12.296.179.591.179.857zm-6.781-8.987c0-.03 0-.088-.03-.147-.926-2.78-1.823-5.47-2.3-6.918-.18-.532-.33-.828-.508-.828-.15 0-.33.266-.538.858-.448 1.182-2.39 6.71-2.39 6.976 0 .118.06.178.239.178.597 0 1.703.03 2.748.03 1.076 0 2.121-.03 2.54-.03.179 0 .239-.03.239-.119z" fill="#3E7FCB"/><ellipse fill="#3E7FCB" cx="61.375" cy="5.609" rx="5.625" ry="5.609"/><ellipse fill="#3E7FCB" cx="6.375" cy="33.033" rx="5.625" ry="5.609"/><ellipse fill="#3E7FCB" cx="58.625" cy="84.391" rx="5.625" ry="5.609"/></g></svg>
</a>

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
