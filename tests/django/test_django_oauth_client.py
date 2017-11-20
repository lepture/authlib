from __future__ import unicode_literals, print_function

from django.test import TestCase, override_settings
from authlib.client.django import OAuth

dev_client = {
    'client_key': 'dev-key',
    'client_secret': 'dev-secret'
}


class DjangoOAuthTest(TestCase):
    def test_register_remote_app(self):
        oauth = OAuth()
        self.assertRaises(AttributeError, lambda: oauth.dev)

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

    @override_settings(AUTHLIB_OAUTH_CLIENTS={'dev': dev_client})
    def test_register_from_settings(self):
        oauth = OAuth()
        oauth.register('dev')
        self.assertEqual(oauth.dev.client_key, 'dev-key')
        self.assertEqual(oauth.dev.client_secret, 'dev-secret')
