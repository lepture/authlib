import time
from flask import json
from authlib.specs.rfc5849 import signature
from authlib.common.urls import add_params_to_uri
from tests.util import get_rsa_private_key
from .oauth1_server import db, User, Client, Token
from .oauth1_server import (
    TestCase,
    create_resource_server,
)


class AuthorizationTest(TestCase):
    def prepare_data(self, use_cache=False):
        create_resource_server(self.app, use_cache)
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

        tok = Token(
            user_id=user.id,
            client_id=client.client_id,
            oauth_token='valid-token',
            oauth_token_secret='valid-token-secret'
        )
        db.session.add(tok)
        db.session.commit()

    def test_invalid_request_parameters(self):
        self.prepare_data(True)
        url = '/user'

        # case 1
        rv = self.client.get(url)
        data = json.loads(rv.data)
        self.assertEqual(data['error'], 'missing_required_parameter')
        self.assertIn('oauth_consumer_key', data['error_description'])

        # case 2
        rv = self.client.get(
            add_params_to_uri(url, {'oauth_consumer_key': 'a'}))
        data = json.loads(rv.data)
        self.assertEqual(data['error'], 'invalid_client')

        # case 3
        rv = self.client.get(
            add_params_to_uri(url, {'oauth_consumer_key': 'client'}))
        data = json.loads(rv.data)
        self.assertEqual(data['error'], 'missing_required_parameter')
        self.assertIn('oauth_token', data['error_description'])

        # case 4
        rv = self.client.get(
            add_params_to_uri(url, {
                'oauth_consumer_key': 'client',
                'oauth_token': 'a'
            })
        )
        data = json.loads(rv.data)
        self.assertEqual(data['error'], 'invalid_token')

        # case 5
        rv = self.client.get(
            add_params_to_uri(url, {
                'oauth_consumer_key': 'client',
                'oauth_token': 'valid-token'
            })
        )
        data = json.loads(rv.data)
        self.assertEqual(data['error'], 'missing_required_parameter')
        self.assertIn('oauth_timestamp', data['error_description'])

    def test_plaintext_signature(self):
        self.prepare_data(True)
        url = '/user'

        # case 1: success
        auth_header = (
            'OAuth oauth_consumer_key="client",'
            'oauth_signature_method="PLAINTEXT",'
            'oauth_token="valid-token",'
            'oauth_signature="secret&valid-token-secret"'
        )
        headers = {'Authorization': auth_header}
        rv = self.client.get(url, headers=headers)
        data = json.loads(rv.data)
        self.assertIn('username', data)

        # case 2: invalid signature
        auth_header = auth_header.replace('valid-token-secret', 'invalid')
        headers = {'Authorization': auth_header}
        rv = self.client.get(url, headers=headers)
        data = json.loads(rv.data)
        self.assertEqual(data['error'], 'invalid_signature')

    def test_hmac_sha1_signature(self):
        self.prepare_data(True)
        url = '/user'

        params = [
            ('oauth_consumer_key', 'client'),
            ('oauth_token', 'valid-token'),
            ('oauth_signature_method', 'HMAC-SHA1'),
            ('oauth_timestamp', str(int(time.time()))),
            ('oauth_nonce', 'hmac-sha1-nonce'),
        ]
        base_string = signature.construct_base_string(
            'GET', 'http://localhost/user', params
        )
        sig = signature.hmac_sha1_signature(
            base_string, 'secret', 'valid-token-secret')
        params.append(('oauth_signature', sig))
        auth_param = ','.join(['{}="{}"'.format(k, v) for k, v in params])
        auth_header = 'OAuth ' + auth_param
        headers = {'Authorization': auth_header}

        # case 1: success
        rv = self.client.get(url, headers=headers)
        data = json.loads(rv.data)
        self.assertIn('username', data)

        # case 2: exists nonce
        rv = self.client.get(url, headers=headers)
        data = json.loads(rv.data)
        self.assertEqual(data['error'], 'invalid_nonce')

    def test_rsa_sha1_signature(self):
        self.prepare_data(True)
        url = '/user'

        params = [
            ('oauth_consumer_key', 'client'),
            ('oauth_token', 'valid-token'),
            ('oauth_signature_method', 'RSA-SHA1'),
            ('oauth_timestamp', str(int(time.time()))),
            ('oauth_nonce', 'rsa-sha1-nonce'),
        ]
        base_string = signature.construct_base_string(
            'GET', 'http://localhost/user', params
        )
        sig = signature.rsa_sha1_signature(base_string, get_rsa_private_key())
        params.append(('oauth_signature', sig))
        auth_param = ','.join(['{}="{}"'.format(k, v) for k, v in params])
        auth_header = 'OAuth ' + auth_param
        headers = {'Authorization': auth_header}
        rv = self.client.get(url, headers=headers)
        data = json.loads(rv.data)
        self.assertIn('username', data)

        # case: invalid signature
        auth_param = auth_param.replace('rsa-sha1-nonce', 'alt-sha1-nonce')
        auth_header = 'OAuth ' + auth_param
        headers = {'Authorization': auth_header}
        rv = self.client.get(url, headers=headers)
        data = json.loads(rv.data)
        self.assertEqual(data['error'], 'invalid_signature')
