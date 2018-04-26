import unittest
import datetime
from authlib.specs.rfc7515 import UnsupportedAlgorithmError
from authlib.specs.rfc7519 import JWT, JWTClaims, jwt
from authlib.specs.rfc7519 import errors


class JWTTest(unittest.TestCase):
    def test_init_algorithms(self):
        _jwt = JWT(['RS256'])
        self.assertRaises(
            UnsupportedAlgorithmError,
            _jwt.encode, {'alg': 'HS256'}, {}, 'k'
        )

        _jwt = JWT('RS256')
        self.assertRaises(
            UnsupportedAlgorithmError,
            _jwt.encode, {'alg': 'HS256'}, {}, 'k'
        )

    def test_encode_sensitive_data(self):
        # check=False won't raise error
        jwt.encode({'alg': 'HS256'}, {'password': ''}, 'k', check=False)
        self.assertRaises(
            errors.InsecureClaimError,
            jwt.encode, {'alg': 'HS256'},  {'password': ''}, 'k'
        )
        self.assertRaises(
            errors.InsecureClaimError,
            jwt.encode, {'alg': 'HS256'}, {'text': '4242424242424242'}, 'k'
        )

    def test_encode_datetime(self):
        now = datetime.datetime.utcnow()
        id_token = jwt.encode({'alg': 'HS256'}, {'exp': now}, 'k')
        claims = jwt.decode(id_token, 'k')
        self.assertIsInstance(claims.exp, int)

    def test_validate_essential_claims(self):
        id_token = jwt.encode({'alg': 'HS256'}, {'iss': 'foo'}, 'k')
        claims_options = {
            'iss': {
                'essential': True,
                'values': ['foo']
            }
        }
        claims = jwt.decode(id_token, 'k', claims_options=claims_options)
        claims.validate()

        claims.options = {'sub': {'essential': True}}
        self.assertRaises(
            errors.MissingClaimError,
            claims.validate
        )

    def test_attribute_error(self):
        claims = JWTClaims({'iss': 'foo'}, {'alg': 'HS256'})
        self.assertRaises(AttributeError, lambda: claims.invalid)

    def test_invalid_values(self):
        id_token = jwt.encode({'alg': 'HS256'}, {'iss': 'foo'}, 'k')
        claims_options = {'iss': {'values': ['bar']}}
        claims = jwt.decode(id_token, 'k', claims_options=claims_options)
        self.assertRaises(
            errors.InvalidClaimError,
            claims.validate,
        )
        claims.options = {'iss': {'value': 'bar'}}
        self.assertRaises(
            errors.InvalidClaimError,
            claims.validate,
        )

    def test_validate_aud(self):
        id_token = jwt.encode({'alg': 'HS256'}, {'aud': 'foo'}, 'k')
        claims_options = {
            'aud': {
                'essential': True,
                'value': 'foo'
            }
        }
        claims = jwt.decode(id_token, 'k', claims_options=claims_options)
        claims.validate()

        claims.options = {
            'aud': {'values': ['bar']}
        }
        self.assertRaises(
            errors.InvalidClaimError,
            claims.validate
        )

        id_token = jwt.encode({'alg': 'HS256'}, {'aud': ['foo', 'bar']}, 'k')
        claims = jwt.decode(id_token, 'k', claims_options=claims_options)
        claims.validate()
        # no validate
        claims.options = {'aud': {'values': []}}
        claims.validate()

    def test_validate_exp(self):
        id_token = jwt.encode({'alg': 'HS256'}, {'exp': 'invalid'}, 'k')
        claims = jwt.decode(id_token, 'k')
        self.assertRaises(
            errors.InvalidClaimError,
            claims.validate
        )

        id_token = jwt.encode({'alg': 'HS256'}, {'exp': 1234}, 'k')
        claims = jwt.decode(id_token, 'k')
        self.assertRaises(
            errors.ExpiredTokenError,
            claims.validate
        )

    def test_validate_nbf(self):
        id_token = jwt.encode({'alg': 'HS256'}, {'nbf': 'invalid'}, 'k')
        claims = jwt.decode(id_token, 'k')
        self.assertRaises(
            errors.InvalidClaimError,
            claims.validate
        )

        id_token = jwt.encode({'alg': 'HS256'}, {'nbf': 1234}, 'k')
        claims = jwt.decode(id_token, 'k')
        claims.validate()

        id_token = jwt.encode({'alg': 'HS256'}, {'nbf': 1234}, 'k')
        claims = jwt.decode(id_token, 'k')
        self.assertRaises(
            errors.InvalidTokenError,
            claims.validate, 123
        )

    def test_validate_iat(self):
        id_token = jwt.encode({'alg': 'HS256'}, {'iat': 'invalid'}, 'k')
        claims = jwt.decode(id_token, 'k')
        self.assertRaises(
            errors.InvalidClaimError,
            claims.validate
        )

    def test_validate_jti(self):
        id_token = jwt.encode({'alg': 'HS256'}, {'jti': 'bar'}, 'k')
        claims_options = {
            'jti': {
                'validate': lambda o: o == 'foo'
            }
        }
        claims = jwt.decode(id_token, 'k', claims_options=claims_options)
        self.assertRaises(
            errors.InvalidClaimError,
            claims.validate
        )
