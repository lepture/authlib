from flask import json
from werkzeug.urls import url_encode
from authlib.common.urls import urlparse, url_decode
from .oauth2_server import db, User, Client
from .oauth2_server import TestCase
from .oauth2_server import OpenIDCodeGrant
from .oauth2_server import create_authorization_server


class OpenIDCodeTest(TestCase):
    def prepare_data(self):
        self.app.config.update({'OAUTH2_OPENID_ENABLED': True})
        server = create_authorization_server(self.app)
        server.register_grant_endpoint(OpenIDCodeGrant)

        user = User(username='foo')
        db.session.add(user)
        db.session.commit()

        client = Client(
            user_id=user.id,
            client_id='code-client',
            client_secret='code-secret',
            redirect_uris='https://a.b',
            scope='openid profile address',
            allowed_response_types='code',
            allowed_grant_types='authorization_code',
        )
        self.authorize_url = (
            '/oauth/authorize?response_type=code'
            '&client_id=code-client'
        )
        db.session.add(client)
        db.session.commit()

    def test_missing_redirect_uri(self):
        self.prepare_data()
        uri = self.authorize_url + '&scope=openid'
        rv = self.client.post(uri, data={'user_id': '1'})
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'invalid_request')

    def test_authorize_token(self):
        # generate refresh token
        self.prepare_data()

        query = url_encode({
            'state': 'bar',
            'scope': 'openid profile',
            'redirect_uri': 'https://a.b'
        })
        url = self.authorize_url + '&' + query
        rv = self.client.post(url, data={'user_id': '1'})
        self.assertIn('code=', rv.location)

        params = dict(url_decode(urlparse.urlparse(rv.location).query))
        self.assertEqual(params['state'], 'bar')

        code = params['code']
        headers = self.create_basic_header('code-client', 'code-secret')
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'authorization_code',
            'redirect_uri': 'https://a.b',
            'code': code,
        }, headers=headers)
        resp = json.loads(rv.data)
        self.assertIn('access_token', resp)
        self.assertIn('id_token', resp)
