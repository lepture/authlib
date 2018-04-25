import mock
from unittest import TestCase
from flask import Flask, session
from authlib.client import OAuthException
from authlib.flask.client import OAuth
from authlib.client.apps import register_apps, get_oauth_app, get_app
from .cache import SimpleCache
from ..client_base import (
    mock_send_value,
    get_bearer_token
)


class FlaskOAuthTest(TestCase):
    def test_register_remote_app(self):
        app = Flask(__name__)
        oauth = OAuth(app)
        self.assertRaises(AttributeError, lambda: oauth.dev)

        oauth.register(
            'dev',
            client_id='dev',
            client_secret='dev',
        )
        self.assertEqual(oauth.dev.name, 'dev')
        self.assertEqual(oauth.dev.client_id, 'dev')

    def test_register_conf_from_app(self):
        app = Flask(__name__)
        app.config.update({
            'DEV_CLIENT_ID': 'dev',
            'DEV_CLIENT_SECRET': 'dev',
        })
        oauth = OAuth(app)
        oauth.register('dev')
        self.assertEqual(oauth.dev.client_id, 'dev')

    def test_init_app_later(self):
        app = Flask(__name__)
        app.config.update({
            'DEV_CLIENT_ID': 'dev',
            'DEV_CLIENT_SECRET': 'dev',
        })
        oauth = OAuth()
        remote = oauth.register('dev')
        self.assertRaises(RuntimeError, lambda: oauth.dev.client_id)
        oauth.init_app(app)
        self.assertEqual(oauth.dev.client_id, 'dev')
        self.assertEqual(remote.client_id, 'dev')

    def test_register_oauth1_remote_app(self):
        app = Flask(__name__)
        oauth = OAuth(app)
        oauth.register(
            'dev',
            client_id='dev',
            client_secret='dev',
            request_token_url='https://i.b/reqeust-token',
            base_url='https://i.b/api',
            access_token_url='https://i.b/token',
            authorize_url='https://i.b/authorize'
        )
        self.assertEqual(oauth.dev.name, 'dev')
        self.assertEqual(oauth.dev.client_id, 'dev')

    def test_register_built_in_app(self):
        app = Flask(__name__)
        app.config.update({
            'TWITTER_CLIENT_ID': 'twitter_key',
            'TWITTER_CLIENT_SECRET': 'twitter_secret',
        })
        oauth = OAuth(app)
        register_apps(oauth, ['twitter'])
        self.assertEqual(oauth.twitter.name, 'twitter')

        twitter = get_oauth_app(oauth, 'twitter')
        self.assertEqual(twitter, get_app('twitter'))
        self.assertEqual(twitter.name, 'twitter')
        self.assertEqual(twitter.client.name, 'twitter')
        self.assertTrue(callable(twitter.profile))

    def test_oauth1_authorize(self):
        app = Flask(__name__)
        app.secret_key = '!'
        oauth = OAuth(app, cache=SimpleCache())
        client = oauth.register(
            'dev',
            client_id='dev',
            client_secret='dev',
            request_token_url='https://i.b/reqeust-token',
            base_url='https://i.b/api',
            access_token_url='https://i.b/token',
            authorize_url='https://i.b/authorize'
        )

        with app.test_request_context():
            with mock.patch('requests.sessions.Session.send') as send:
                send.return_value = mock_send_value('oauth_token=foo&oauth_verifier=baz')
                resp = client.authorize_redirect('https://b.com/bar')
                self.assertEqual(resp.status_code, 302)
                url = resp.headers.get('Location')
                self.assertIn('oauth_token=foo', url)
                self.assertIsNotNone(session.get('_dev_req_token_'))

            with mock.patch('requests.sessions.Session.send') as send:
                send.return_value = mock_send_value('oauth_token=a&oauth_token_secret=b')
                token = client.authorize_access_token()
                self.assertEqual(token['oauth_token'], 'a')

    def test_register_oauth2_remote_app(self):
        app = Flask(__name__)
        oauth = OAuth(app)
        oauth.register(
            'dev',
            client_id='dev',
            client_secret='dev',
            base_url='https://i.b/api',
            access_token_url='https://i.b/token',
            refresh_token_url='https://i.b/token',
            authorize_url='https://i.b/authorize',
            update_token=lambda o: o
        )
        self.assertEqual(oauth.dev.name, 'dev')
        session = oauth.dev._get_session()
        self.assertIsNotNone(session.token_updater)

    def test_oauth2_authorize(self):
        app = Flask(__name__)
        app.secret_key = '!'
        oauth = OAuth(app)
        client = oauth.register(
            'dev',
            client_id='dev',
            client_secret='dev',
            base_url='https://i.b/api',
            access_token_url='https://i.b/token',
            authorize_url='https://i.b/authorize'
        )

        with app.test_request_context():
            resp = client.authorize_redirect('https://b.com/bar')
            self.assertEqual(resp.status_code, 302)
            url = resp.headers.get('Location')
            self.assertIn('state=', url)
            state = session['_dev_state_']
            self.assertIsNotNone(state)

        with app.test_request_context(path='/?code=a&state={}'.format(state)):
            self.assertRaises(OAuthException, client.authorize_access_token)
            # session is cleared in tests
            session['_dev_state_'] = state

            with mock.patch('requests.sessions.Session.send') as send:
                send.return_value = mock_send_value(get_bearer_token())
                token = client.authorize_access_token()
                self.assertEqual(token['access_token'], 'a')

        with app.test_request_context():
            self.assertEqual(client.token, None)

    def test_oauth2_access_token_with_post(self):
        app = Flask(__name__)
        app.secret_key = '!'
        oauth = OAuth(app)
        client = oauth.register(
            'dev',
            client_id='dev',
            client_secret='dev',
            base_url='https://i.b/api',
            access_token_url='https://i.b/token',
            authorize_url='https://i.b/authorize'
        )
        payload = {'code': 'a', 'state': 'b'}
        with app.test_request_context(data=payload, method='POST'):
            session['_dev_state_'] = 'b'
            with mock.patch('requests.sessions.Session.send') as send:
                send.return_value = mock_send_value(get_bearer_token())
                token = client.authorize_access_token()
                self.assertEqual(token['access_token'], 'a')
