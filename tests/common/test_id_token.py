from __future__ import unicode_literals, print_function
import unittest
from authlib.specs.oidc import (
    parse_id_token, validate_id_token, verify_id_token,
    IDTokenError, CodeIDToken,
)


# http://openid.net/specs/openid-connect-core-1_0.html#ExampleRSAKey
JWK_RSA_PUB_KEY = {
   'kty': 'RSA',
   'kid': '1e9gdk7',
   'n': (
       'w7Zdfmece8iaB0kiTY8pCtiBtzbptJmP28nSWwtdjRu0f2GFpajvWE4VhfJA'
        'jEsOcwYzay7XGN0b-X84BfC8hmCTOj2b2eHT7NsZegFPKRUQzJ9wW8ipn_aD'
        'JWMGDuB1XyqT1E7DYqjUCEOD1b4FLpy_xPn6oV_TYOfQ9fZdbE5HGxJUzeku'
        'GcOKqOQ8M7wfYHhHHLxGpQVgL0apWuP2gDDOdTtpuld4D2LK1MZK99s9gaSj'
        'RHE8JDb1Z4IGhEcEyzkxswVdPndUWzfvWBBWXWxtSUvQGBRkuy1BHOa4sP6F'
        'KjWEeeF7gm7UMs2Nm2QUgNZw6xvEDGaLk4KASdIxRQ'
   ),
   'e': 'AQAB'
}

# http://openid.net/specs/openid-connect-core-1_0.html#id_tokenExample
ID_TOKEN = (
    'eyJraWQiOiIxZTlnZGs3IiwiYWxnIjoiUlMyNTYifQ.ewogImlz'
    'cyI6ICJodHRwOi8vc2VydmVyLmV4YW1wbGUuY29tIiwKICJzdWIiOiAiMjQ4'
    'Mjg5NzYxMDAxIiwKICJhdWQiOiAiczZCaGRSa3F0MyIsCiAibm9uY2UiOiAi'
    'bi0wUzZfV3pBMk1qIiwKICJleHAiOiAxMzExMjgxOTcwLAogImlhdCI6IDEz'
    'MTEyODA5NzAsCiAibmFtZSI6ICJKYW5lIERvZSIsCiAiZ2l2ZW5fbmFtZSI6'
    'ICJKYW5lIiwKICJmYW1pbHlfbmFtZSI6ICJEb2UiLAogImdlbmRlciI6ICJm'
    'ZW1hbGUiLAogImJpcnRoZGF0ZSI6ICIwMDAwLTEwLTMxIiwKICJlbWFpbCI6'
    'ICJqYW5lZG9lQGV4YW1wbGUuY29tIiwKICJwaWN0dXJlIjogImh0dHA6Ly9l'
    'eGFtcGxlLmNvbS9qYW5lZG9lL21lLmpwZyIKfQ.rHQjEmBqn9Jre0OLykYNn'
    'spA10Qql2rvx4FsD00jwlB0Sym4NzpgvPKsDjn_wMkHxcp6CilPcoKrWHcip'
    'R2iAjzLvDNAReF97zoJqq880ZD1bwY82JDauCXELVR9O6_B0w3K-E7yM2mac'
    'AAgNCUwtik6SjoSUZRcf-O5lygIyLENx882p6MtmwaL1hd6qn5RZOQ0TLrOY'
    'u0532g9Exxcm-ChymrB4xLykpDj3lUivJt63eEGGN6DH5K6o33TcxkIjNrCD'
    '4XB1CKKumZvCedgHHF3IAK4dVEDSUoGlH9z4pP_eWYNXvqQOjGs-rDaQzUHl'
    '6cQQWNiDpWOl_lxXjQEvQ'
)


class OAuthClientTest(unittest.TestCase):
    def test_parse_id_token(self):
        rv = parse_id_token(ID_TOKEN, JWK_RSA_PUB_KEY)
        self.assertIsInstance(rv, tuple)

    def test_verify_id_token(self):
        self.assertRaises(ValueError, lambda: verify_id_token({}, ''))
        response = {'id_token': ID_TOKEN}
        token = verify_id_token(response, JWK_RSA_PUB_KEY)
        self.assertIsInstance(token, CodeIDToken)

    def test_validate_id_token(self):
        self.assertRaises(ValueError, lambda: validate_id_token({}, 'n'))
