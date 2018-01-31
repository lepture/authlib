import time
from authlib.specs.rfc5849 import signature
from tests.util import get_rsa_private_key
from .oauth1_server import db, User, Client
from .oauth1_server import (
    TestCase,
    create_authorization_server,
    decode_response
)


class AuthorizationTest(TestCase):
    def prepare_data(self, use_cache=False):
        self.server = create_authorization_server(self.app, use_cache)
        user = User(username='foo')
        db.session.add(user)
        db.session.commit()
        client = Client(
            user_id=user.id,
            client_id='client',
            client_secret='secret',
            default_redirect_uri='https://a.b',
        )
        db.session.add(client)
        db.session.commit()

    def prepare_temporary_credential(self):
        credential = {
            'oauth_token': 'abc',
            'oauth_token_secret': 'abc-secret',
            'oauth_verifier': 'abc-verifier',
            'user': 1
        }
        self.server._create_cache_temporary_credential(
            credential, 'client', 'oob'
        )

    def test_invalid_token_request_parameters(self):
        self.prepare_data(True)
        url = '/oauth/token'

        # case 1
        rv = self.client.post(url)
        data = decode_response(rv.data)
        self.assertEqual(data['error'], 'missing_required_parameter')
        self.assertIn('oauth_consumer_key', data['error_description'])

        # case 2
        rv = self.client.post(url, data={'oauth_consumer_key': 'a'})
        data = decode_response(rv.data)
        self.assertEqual(data['error'], 'invalid_client')

        # case 3
        rv = self.client.post(url, data={'oauth_consumer_key': 'client'})
        data = decode_response(rv.data)
        self.assertEqual(data['error'], 'missing_required_parameter')
        self.assertIn('oauth_token', data['error_description'])

        # case 4
        rv = self.client.post(url, data={
            'oauth_consumer_key': 'client',
            'oauth_token': 'a'
        })
        data = decode_response(rv.data)
        self.assertEqual(data['error'], 'invalid_token')

    def test_invalid_token_and_verifiers(self):
        self.prepare_data(True)
        url = '/oauth/token'

        # case 5
        self.server._create_cache_temporary_credential(
            {'oauth_token': 'abc', 'oauth_token_secret': 'abc-secret'},
            'client', 'oob'
        )
        rv = self.client.post(url, data={
            'oauth_consumer_key': 'client',
            'oauth_token': 'abc'
        })
        data = decode_response(rv.data)
        self.assertEqual(data['error'], 'missing_required_parameter')
        self.assertIn('oauth_verifier', data['error_description'])

        # case 6
        self.server._create_cache_temporary_credential(
            {'oauth_token': 'abc', 'oauth_token_secret': 'abc-secret'},
            'client', 'oob'
        )
        rv = self.client.post(url, data={
            'oauth_consumer_key': 'client',
            'oauth_token': 'abc',
            'oauth_verifier': 'abc'
        })
        data = decode_response(rv.data)
        self.assertEqual(data['error'], 'invalid_request')
        self.assertIn('oauth_verifier', data['error_description'])

    def test_duplicated_oauth_parameters(self):
        self.prepare_data(True)
        url = '/oauth/token?oauth_consumer_key=client'
        rv = self.client.post(url, data={
            'oauth_consumer_key': 'client',
            'oauth_token': 'abc',
            'oauth_verifier': 'abc'
        })
        data = decode_response(rv.data)
        self.assertEqual(data['error'], 'duplicated_oauth_protocol_parameter')

    def test_plaintext_signature(self):
        self.prepare_data(True)
        url = '/oauth/token'

        # case 1: success
        self.prepare_temporary_credential()
        auth_header = (
            'OAuth oauth_consumer_key="client",'
            'oauth_signature_method="PLAINTEXT",'
            'oauth_token="abc",'
            'oauth_verifier="abc-verifier",'
            'oauth_signature="secret&abc-secret"'
        )
        headers = {'Authorization': auth_header}
        rv = self.client.post(url, headers=headers)
        data = decode_response(rv.data)
        self.assertIn('oauth_token', data)

        # case 2: invalid signature
        self.prepare_temporary_credential()
        rv = self.client.post(url, data={
            'oauth_consumer_key': 'client',
            'oauth_signature_method': 'PLAINTEXT',
            'oauth_token': 'abc',
            'oauth_verifier': 'abc-verifier',
            'oauth_signature': 'invalid-signature'
        })
        data = decode_response(rv.data)
        self.assertEqual(data['error'], 'invalid_signature')

    def test_hmac_sha1_signature(self):
        self.prepare_data(True)
        url = '/oauth/token'

        params = [
            ('oauth_consumer_key', 'client'),
            ('oauth_token', 'abc'),
            ('oauth_verifier', 'abc-verifier'),
            ('oauth_signature_method', 'HMAC-SHA1'),
            ('oauth_timestamp', str(int(time.time()))),
            ('oauth_nonce', 'hmac-sha1-nonce'),
        ]
        base_string = signature.construct_base_string(
            'POST', 'http://localhost/oauth/token', params
        )
        sig = signature.hmac_sha1_signature(
            base_string, 'secret', 'abc-secret')
        params.append(('oauth_signature', sig))
        auth_param = ','.join(['{}="{}"'.format(k, v) for k, v in params])
        auth_header = 'OAuth ' + auth_param
        headers = {'Authorization': auth_header}

        # case 1: success
        self.prepare_temporary_credential()
        rv = self.client.post(url, headers=headers)
        data = decode_response(rv.data)
        self.assertIn('oauth_token', data)

        # case 2: exists nonce
        self.prepare_temporary_credential()
        rv = self.client.post(url, headers=headers)
        data = decode_response(rv.data)
        self.assertEqual(data['error'], 'invalid_nonce')

    def test_rsa_sha1_signature(self):
        self.prepare_data(True)
        url = '/oauth/token'

        self.prepare_temporary_credential()
        params = [
            ('oauth_consumer_key', 'client'),
            ('oauth_token', 'abc'),
            ('oauth_verifier', 'abc-verifier'),
            ('oauth_signature_method', 'RSA-SHA1'),
            ('oauth_timestamp', str(int(time.time()))),
            ('oauth_nonce', 'rsa-sha1-nonce'),
        ]
        base_string = signature.construct_base_string(
            'POST', 'http://localhost/oauth/token', params
        )
        sig = signature.rsa_sha1_signature(base_string, get_rsa_private_key())
        params.append(('oauth_signature', sig))
        auth_param = ','.join(['{}="{}"'.format(k, v) for k, v in params])
        auth_header = 'OAuth ' + auth_param
        headers = {'Authorization': auth_header}
        rv = self.client.post(url, headers=headers)
        data = decode_response(rv.data)
        self.assertIn('oauth_token', data)

        # case: invalid signature
        self.prepare_temporary_credential()
        auth_param = auth_param.replace('rsa-sha1-nonce', 'alt-sha1-nonce')
        auth_header = 'OAuth ' + auth_param
        headers = {'Authorization': auth_header}
        rv = self.client.post(url, headers=headers)
        data = decode_response(rv.data)
        self.assertEqual(data['error'], 'invalid_signature')
