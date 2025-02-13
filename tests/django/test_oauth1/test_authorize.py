from django.test import override_settings

from authlib.oauth1.rfc5849 import errors
from tests.util import decode_response

from .models import Client
from .models import User
from .oauth1_server import TestCase


class AuthorizationTest(TestCase):
    def prepare_data(self):
        user = User(username="foo")
        user.save()
        client = Client(
            user_id=user.pk,
            client_id="client",
            client_secret="secret",
            default_redirect_uri="https://a.b",
        )
        client.save()

    def test_invalid_authorization(self):
        server = self.create_server()
        url = "/oauth/authorize"
        request = self.factory.post(url)
        self.assertRaises(
            errors.MissingRequiredParameterError,
            server.check_authorization_request,
            request,
        )

        request = self.factory.post(url, data={"oauth_token": "a"})
        self.assertRaises(
            errors.InvalidTokenError, server.check_authorization_request, request
        )

    def test_invalid_initiate(self):
        server = self.create_server()
        url = "/oauth/initiate"
        request = self.factory.post(
            url,
            data={
                "oauth_consumer_key": "client",
                "oauth_callback": "oob",
                "oauth_signature_method": "PLAINTEXT",
                "oauth_signature": "secret&",
            },
        )
        resp = server.create_temporary_credentials_response(request)
        data = decode_response(resp.content)
        self.assertEqual(data["error"], "invalid_client")

    @override_settings(AUTHLIB_OAUTH1_PROVIDER={"signature_methods": ["PLAINTEXT"]})
    def test_authorize_denied(self):
        self.prepare_data()
        server = self.create_server()
        initiate_url = "/oauth/initiate"
        authorize_url = "/oauth/authorize"

        # case 1
        request = self.factory.post(
            initiate_url,
            data={
                "oauth_consumer_key": "client",
                "oauth_callback": "oob",
                "oauth_signature_method": "PLAINTEXT",
                "oauth_signature": "secret&",
            },
        )
        resp = server.create_temporary_credentials_response(request)
        data = decode_response(resp.content)
        self.assertIn("oauth_token", data)

        request = self.factory.post(
            authorize_url, data={"oauth_token": data["oauth_token"]}
        )
        resp = server.create_authorization_response(request)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("access_denied", resp["Location"])
        self.assertIn("https://a.b", resp["Location"])

        # case 2
        request = self.factory.post(
            initiate_url,
            data={
                "oauth_consumer_key": "client",
                "oauth_callback": "https://i.test",
                "oauth_signature_method": "PLAINTEXT",
                "oauth_signature": "secret&",
            },
        )
        resp = server.create_temporary_credentials_response(request)
        data = decode_response(resp.content)
        self.assertIn("oauth_token", data)
        request = self.factory.post(
            authorize_url, data={"oauth_token": data["oauth_token"]}
        )
        resp = server.create_authorization_response(request)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("access_denied", resp["Location"])
        self.assertIn("https://i.test", resp["Location"])

    @override_settings(AUTHLIB_OAUTH1_PROVIDER={"signature_methods": ["PLAINTEXT"]})
    def test_authorize_granted(self):
        self.prepare_data()
        server = self.create_server()
        user = User.objects.get(username="foo")
        initiate_url = "/oauth/initiate"
        authorize_url = "/oauth/authorize"

        # case 1
        request = self.factory.post(
            initiate_url,
            data={
                "oauth_consumer_key": "client",
                "oauth_callback": "oob",
                "oauth_signature_method": "PLAINTEXT",
                "oauth_signature": "secret&",
            },
        )
        resp = server.create_temporary_credentials_response(request)
        data = decode_response(resp.content)
        self.assertIn("oauth_token", data)

        request = self.factory.post(
            authorize_url, data={"oauth_token": data["oauth_token"]}
        )
        resp = server.create_authorization_response(request, user)
        self.assertEqual(resp.status_code, 302)

        self.assertIn("oauth_verifier", resp["Location"])
        self.assertIn("https://a.b", resp["Location"])

        # case 2
        request = self.factory.post(
            initiate_url,
            data={
                "oauth_consumer_key": "client",
                "oauth_callback": "https://i.test",
                "oauth_signature_method": "PLAINTEXT",
                "oauth_signature": "secret&",
            },
        )
        resp = server.create_temporary_credentials_response(request)
        data = decode_response(resp.content)
        self.assertIn("oauth_token", data)

        request = self.factory.post(
            authorize_url, data={"oauth_token": data["oauth_token"]}
        )
        resp = server.create_authorization_response(request, user)

        self.assertEqual(resp.status_code, 302)
        self.assertIn("oauth_verifier", resp["Location"])
        self.assertIn("https://i.test", resp["Location"])
