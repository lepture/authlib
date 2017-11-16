from __future__ import unicode_literals, print_function
from unittest import TestCase
from flask import Flask, session
from authlib.client import OAuthException
from authlib.client.flask import OAuth
from ..client_base import (
    mock_json_response,
    mock_text_response,
    get_bearer_token
)


class FlaskOAuthTest(TestCase):
    def test_register_remote_app(self):
        app = Flask(__name__)
        oauth = OAuth(app)
        self.assertRaises(AttributeError, lambda: oauth.dev)

        oauth.register(
            'dev',
            client_key='dev',
            client_secret='dev',
        )
        self.assertEqual(oauth.dev.name, 'dev')
        self.assertEqual(oauth.dev.client_key, 'dev')

    def test_register_conf_from_app(self):
        app = Flask(__name__)
        app.config.update({
            'DEV_CLIENT_KEY': 'dev',
            'DEV_CLIENT_SECRET': 'dev',
        })
        oauth = OAuth(app)
        oauth.register('dev')
        self.assertEqual(oauth.dev.client_key, 'dev')

    def test_init_app_later(self):
        app = Flask(__name__)
        app.config.update({
            'DEV_CLIENT_KEY': 'dev',
            'DEV_CLIENT_SECRET': 'dev',
        })
        oauth = OAuth()
        remote = oauth.register('dev')
        self.assertRaises(RuntimeError, lambda: oauth.dev.client_key)
        oauth.init_app(app)
        self.assertEqual(oauth.dev.client_key, 'dev')
        self.assertEqual(remote.client_key, 'dev')

    def test_register_oauth1_remote_app(self):
        app = Flask(__name__)
        app.config.update({'OAUTH_CLIENT_CACHE_TYPE': 'null'})
        oauth = OAuth(app)
        oauth.register(
            'dev',
            client_key='dev',
            client_secret='dev',
            request_token_url='https://i.b/reqeust-token',
            base_url='https://i.b/api',
            access_token_url='https://i.b/token',
            authorize_url='https://i.b/authorize'
        )
        self.assertEqual(oauth.dev.name, 'dev')
        self.assertEqual(oauth.dev.client_key, 'dev')

    def test_oauth1_authorize(self):
        app = Flask(__name__)
        app.secret_key = '!'
        app.config.update({'OAUTH_CLIENT_CACHE_TYPE': 'simple'})
        oauth = OAuth(app)
        client = oauth.register(
            'dev',
            client_key='dev',
            client_secret='dev',
            request_token_url='https://i.b/reqeust-token',
            base_url='https://i.b/api',
            access_token_url='https://i.b/token',
            authorize_url='https://i.b/authorize'
        )

        client.session.send = mock_text_response(
            'oauth_token=foo&oauth_verifier=baz'
        )

        with app.test_request_context():
            resp = client.authorize_redirect('https://b.com/bar')
            self.assertEqual(resp.status_code, 302)
            url = resp.headers.get('Location')
            self.assertIn('oauth_token=foo', url)
            self.assertIsNotNone(session.get('_dev_req_token_'))

            client.session.send = mock_text_response(
                'oauth_token=a&oauth_token_secret=b'
            )
            token = client.authorize_access_token()
            self.assertEqual(token['oauth_token'], 'a')

    def test_oauth2_authorize(self):
        app = Flask(__name__)
        app.secret_key = '!'
        oauth = OAuth(app)
        client = oauth.register(
            'dev',
            client_key='dev',
            client_secret='dev',
            base_url='https://i.b/api',
            access_token_url='https://i.b/token',
            authorize_url='https://i.b/authorize'
        )
        client.session.send = mock_json_response(get_bearer_token())

        with app.test_request_context():
            resp = client.authorize_redirect('https://b.com/bar')
            self.assertEqual(resp.status_code, 302)
            url = resp.headers.get('Location')
            self.assertIn('state=', url)
            state = session['_dev_state_']
            self.assertIsNotNone(state)

        with app.test_request_context(path='/?state={}'.format(state)):
            self.assertRaises(OAuthException, client.authorize_access_token)
            # session is cleared in tests
            session['_dev_state_'] = state
            token = client.authorize_access_token()
            self.assertEqual(token['access_token'], 'a')
