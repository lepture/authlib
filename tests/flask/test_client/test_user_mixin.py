import mock
from unittest import TestCase
from flask import Flask, session
from authlib.jose import jwk
from authlib.integrations.flask_client import OAuth
from authlib.oidc.core.grants.util import generate_id_token
from tests.client_base import (
    get_bearer_token,
)


class FlaskUserMixinTest(TestCase):
    def run_fetch_userinfo(self, payload, compliance_fix=None):
        app = Flask(__name__)
        app.secret_key = '!'
        oauth = OAuth(app)
        client = oauth.register(
            'dev',
            client_id='dev',
            client_secret='dev',
            fetch_token=get_bearer_token,
            userinfo_endpoint='https://i.b/userinfo',
            userinfo_compliance_fix=compliance_fix,
        )

        def fake_send(sess, req, **kwargs):
            resp = mock.MagicMock()
            resp.json = lambda: payload
            resp.status_code = 200
            return resp

        with app.test_request_context():
            with mock.patch('requests.sessions.Session.send', fake_send):
                user = client.userinfo()
                self.assertEqual(user.sub, '123')

    def test_fetch_userinfo(self):
        self.run_fetch_userinfo({'sub': '123'})

    def test_userinfo_compliance_fix(self):
        def _fix(remote, data):
            return {'sub': data['id']}

        self.run_fetch_userinfo({'id': '123'}, _fix)

    def test_parse_id_token(self):
        key = jwk.dumps('secret', 'oct', kid='f')
        token = get_bearer_token()
        id_token = generate_id_token(
            token, {'sub': '123'}, key,
            alg='HS256', iss='https://i.b',
            aud='dev', exp=3600, nonce='n',
        )

        app = Flask(__name__)
        app.secret_key = '!'
        oauth = OAuth(app)
        client = oauth.register(
            'dev',
            client_id='dev',
            client_secret='dev',
            fetch_token=get_bearer_token,
            jwks={'keys': [key]},
            issuer='https://i.b',
            id_token_signing_alg_values_supported=['HS256', 'RS256'],
        )
        with app.test_request_context():
            session['_dev_authlib_nonce_'] = 'n'
            self.assertIsNone(client.parse_id_token(token))

            token['id_token'] = id_token
            user = client.parse_id_token(token)
            self.assertEqual(user.sub, '123')
