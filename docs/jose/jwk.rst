.. _jwk_guide:

JSON Web Key (JWK)
==================

.. module:: authlib.jose.rfc7517
    :noindex:

A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data structure
that represents a cryptographic key. An example would help a lot::

    {
      "kty": "EC",
      "crv": "P-256",
      "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
      "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
      "kid": "iss-a"
    }

This is an Elliptic Curve Public Key represented by JSON data structure. How
do we ``dumps`` a key into JWK, and ``loads`` JWK back into key? The interface
of :class:`JWK` contains these two methods.

Algorithms for ``kty`` (Key Type) is defined by :ref:`specs/rfc7518`.
Available ``kty`` values are: **EC**, **RSA** and **oct**. Initialize a JWK
instance with JWA::

    from authlib.jose import JWK
    from authlib.jose import JWK_ALGORITHMS

    jwk = JWK(algorithms=JWK_ALGORITHMS)
    key = read_file('public.pem')
    obj = jwk.dumps(key, kty='RSA')
    # obj is a dict, you may turn it into JSON
    key = jwk.loads(obj)

There is an ``jwk`` instance in ``authlib.jose``, so that you don't need to
initialize JWK yourself, try::

    from authlib.jose import jwk
    key = read_file('public.pem')
    obj = jwk.dumps(key, kty='RSA')
    # obj is a dict, you may turn it into JSON
    key = jwk.loads(obj)

You may pass extra parameters into ``dumps`` method, available parameters can
be found on RFC7517 `Section 4`_.

.. _`Section 4`: https://tools.ietf.org/html/rfc7517#section-4
