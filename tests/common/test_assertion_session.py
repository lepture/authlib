import mock
import time
from unittest import TestCase
from authlib.client import AssertionSession


class AssertionSessionTest(TestCase):

    def setUp(self):
        self.token = {
            'token_type': 'Bearer',
            'access_token': 'a',
            'refresh_token': 'b',
            'expires_in': '3600',
            'expires_at': int(time.time()) + 3600,
        }

    def test_refresh_token(self):
        def verifier(r, **kwargs):
            resp = mock.MagicMock()
            if r.url == 'https://i.b/token':
                self.assertIn('assertion=', r.body)
                resp.json = lambda: self.token
            return resp

        sess = AssertionSession(
            token_url='https://i.b/token',
            grant_type=AssertionSession.JWT_BEARER_GRANT_TYPE,
            issuer='foo',
            subject='foo',
            audience='foo',
            alg='HS256',
            key='secret',
        )
        sess.send = verifier
        sess.get('https://i.b')
