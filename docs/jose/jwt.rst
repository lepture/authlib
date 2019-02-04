.. _jwt_guide:

JSON Web Token (JWT)
====================

.. module:: authlib.jose.rfc7519


JSON Web Token (JWT) is structured by :ref:`specs/rfc7515` or :`specs/rfc7516`
with certain payload claims. The JWT implementation in Authlib has all
built-in algorithms via :ref:`specs/rfc7518`, it can also load private/public
keys of :ref:`specs/rfc7517`::

    >>> from authlib.jose import jwt
    >>> header = {'alg': 'RS256'}
    >>> payload = {'iss': 'Authlib', 'sub': '123', ...}
    >>> key = read_file('private.pem')
    >>> s = jwt.encode(header, payload, key)
    >>> claims = jwt.decode(s, read_file('public.pem'))
    >>> print(claims)
    {'iss': 'Authlib', 'sub': '123', ...}
    >>> print(claims.header)
    {'alg': 'RS256', 'typ': 'JWT'}
    >>> claims.validate()

The imported ``jwt`` is an instance of :class:`JWT`. It has all supported JWS
algorithms, and it can handle JWK automatically. When :meth:`JWT.encode` a
payload, JWT will check payload claims for security, if you really want to
expose them, you can always turn it off via ``check=False``.

.. important::
    JWT payload with JWS is not encrypted, it is just signed. Anyone can
    extract the payload without any private or public keys. Adding sensitive
    data like passwords, social security numbers in JWT payload is not safe
    if you are going to send them in a non-secure connection.

    You can also use JWT with JWE which is encrypted. But this feature is not
    mature, documentation is not provided yet.

JWT Payload Claims Validation
-----------------------------

:meth:`JWT.decode` accepts 3 claims-related parameters: ``claims_cls``,
``claims_option`` and ``claims_params``. The default ``claims_cls`` is
:class:`JWTClaims`. The ``decode`` method returns::

    >>> JWTClaims(payload, header, options=claims_options, params=claims_params)

Claims validation is actually handled by :meth:`JWTClaims.validate`, which
validates payload claims with ``claims_option`` and ``claims_params``. For
standard JWTClaims, ``claims_params`` value is not used, but it is used in
:class:`~authlib.specs.oidc.IDToken`.

Here is an example of ``claims_option``::

    {
        "iss": {
            "essential": True,
            "values": ["https://example.com", "https://example.org"]
        },
        "sub": {
            "essential": True
            "value": "248289761001"
        },
        "jti": {
            "validate": validate_jti
        }
    }

It is a dict configuration, the option key is the name of a claim.

- **essential**: this value is REQUIRED.
- **values**: claim value can be any one in the values list.
- **value**: claim value MUST be the same value.
- **validate**: a function to validate the claim value.
