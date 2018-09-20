import unittest
from authlib.specs.rfc8414 import WELL_KNOWN_URL, get_well_known_url
from authlib.specs.rfc8414 import AuthorizationServerMetadata


class WellKnownTest(unittest.TestCase):
    def test_no_suffix_issuer(self):
        self.assertEqual(
            get_well_known_url('https://authlib.org'),
            WELL_KNOWN_URL
        )
        self.assertEqual(
            get_well_known_url('https://authlib.org/'),
            WELL_KNOWN_URL
        )

    def test_with_suffix_issuer(self):
        self.assertEqual(
            get_well_known_url('https://authlib.org/issuer1'),
            WELL_KNOWN_URL + '/issuer1'
        )
        self.assertEqual(
            get_well_known_url('https://authlib.org/a/b/c'),
            WELL_KNOWN_URL + '/a/b/c'
        )


class AuthorizationServerMetadataTest(unittest.TestCase):
    def test_issuer(self):
        #: missing
        metadata = AuthorizationServerMetadata({})
        with self.assertRaises(ValueError) as cm:
            metadata.validate()
        self.assertEqual('"issuer" is required', str(cm.exception))

        #: https
        metadata = AuthorizationServerMetadata({
            'issuer': 'http://authlib.org/'
        })
        with self.assertRaises(ValueError) as cm:
            metadata.validate_issuer()
        self.assertIn('https', str(cm.exception))

        #: query
        metadata = AuthorizationServerMetadata({
            'issuer': 'https://authlib.org/?a=b'
        })
        with self.assertRaises(ValueError) as cm:
            metadata.validate_issuer()
        self.assertIn('query', str(cm.exception))

        #: fragment
        metadata = AuthorizationServerMetadata({
            'issuer': 'https://authlib.org/#a=b'
        })
        with self.assertRaises(ValueError) as cm:
            metadata.validate_issuer()
        self.assertIn('fragment', str(cm.exception))

        metadata = AuthorizationServerMetadata({
            'issuer': 'https://authlib.org/'
        })
        metadata.validate_issuer()
