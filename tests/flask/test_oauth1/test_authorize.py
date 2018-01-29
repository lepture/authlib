from .oauth1_server import db, User, Client
from .oauth1_server import (
    TestCase,
    create_authorization_server,
    decode_response
)


class AuthorizationTest(TestCase):
    def prepare_data(self, use_cache=False):
        create_authorization_server(self.app, use_cache)
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

    def test_invalid_authorization(self):
        self.prepare_data(True)
        url = '/oauth/authorize'

        # case 1
        rv = self.client.post(url, data={'user_id': '1'})
        data = decode_response(rv.data)
        self.assertEqual(data['error'], 'missing_required_parameter')
        self.assertIn('oauth_token', data['error_description'])

        # case 2
        rv = self.client.post(url, data={'user_id': '1', 'oauth_token': 'a'})
        data = decode_response(rv.data)
        self.assertEqual(data['error'], 'invalid_token')

    def test_authorize_denied(self):
        self.prepare_data(True)
        initiate_url = '/oauth/initiate'
        authorize_url = '/oauth/authorize'

        rv = self.client.post(initiate_url, data={
            'oauth_consumer_key': 'client',
            'oauth_callback': 'oob',
            'oauth_signature_method': 'PLAINTEXT',
            'oauth_signature': 'secret&'
        })
        data = decode_response(rv.data)
        self.assertIn('oauth_token', data)

        rv = self.client.post(authorize_url, data={
            'oauth_token': data['oauth_token']
        })
        self.assertEqual(rv.status_code, 302)
        self.assertIn('access_denied', rv.headers['Location'])
        self.assertIn('https://a.b', rv.headers['Location'])

        rv = self.client.post(initiate_url, data={
            'oauth_consumer_key': 'client',
            'oauth_callback': 'https://i.test',
            'oauth_signature_method': 'PLAINTEXT',
            'oauth_signature': 'secret&'
        })
        data = decode_response(rv.data)
        self.assertIn('oauth_token', data)

        rv = self.client.post(authorize_url, data={
            'oauth_token': data['oauth_token']
        })
        self.assertEqual(rv.status_code, 302)
        self.assertIn('access_denied', rv.headers['Location'])
        self.assertIn('https://i.test', rv.headers['Location'])

    def test_authorize_granted(self):
        self.prepare_data(True)
        initiate_url = '/oauth/initiate'
        authorize_url = '/oauth/authorize'

        rv = self.client.post(initiate_url, data={
            'oauth_consumer_key': 'client',
            'oauth_callback': 'oob',
            'oauth_signature_method': 'PLAINTEXT',
            'oauth_signature': 'secret&'
        })
        data = decode_response(rv.data)
        self.assertIn('oauth_token', data)

        rv = self.client.post(authorize_url, data={
            'user_id': '1',
            'oauth_token': data['oauth_token']
        })
        self.assertEqual(rv.status_code, 302)
        self.assertIn('oauth_verifier', rv.headers['Location'])
        self.assertIn('https://a.b', rv.headers['Location'])

        rv = self.client.post(initiate_url, data={
            'oauth_consumer_key': 'client',
            'oauth_callback': 'https://i.test',
            'oauth_signature_method': 'PLAINTEXT',
            'oauth_signature': 'secret&'
        })
        data = decode_response(rv.data)
        self.assertIn('oauth_token', data)

        rv = self.client.post(authorize_url, data={
            'user_id': '1',
            'oauth_token': data['oauth_token']
        })
        self.assertEqual(rv.status_code, 302)
        self.assertIn('oauth_verifier', rv.headers['Location'])
        self.assertIn('https://i.test', rv.headers['Location'])
