import mock
from unittest import TestCase
from starlette.applications import Starlette as App
from starlette.requests import Request
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth
from tests.client_base import mock_send_value, get_bearer_token


class StarletteOAuthTest(TestCase):
    def test_register_remote_app(self):
        oauth = OAuth()
        self.assertRaises(AttributeError, lambda: oauth.dev)

        oauth.register("dev", client_id="dev", client_secret="dev")
        self.assertEqual(oauth.dev.name, "dev")
        self.assertEqual(oauth.dev.client_id, "dev")

    def test_register_oauth1_remote_app(self):
        app = App()
        app.add_middleware(SessionMiddleware, secret_key="xxxxx")
        oauth = OAuth()
        oauth.register(
            "dev",
            client_id="dev",
            client_secret="dev",
            request_token_url="https://i.b/reqeust-token",
            api_base_url="https://i.b/api",
            access_token_url="https://i.b/token",
            authorize_url="https://i.b/authorize",
        )
        self.assertEqual(oauth.dev.name, "dev")
        self.assertEqual(oauth.dev.client_id, "dev")

    def test_oauth1_authorize(self):
        app = App()
        app.add_middleware(SessionMiddleware, secret_key="xxxxx")
        oauth = OAuth()
        client = oauth.register(
            "dev",
            client_id="dev",
            client_secret="dev",
            request_token_url="https://i.b/reqeust-token",
            api_base_url="https://i.b/api",
            access_token_url="https://i.b/token",
            authorize_url="https://i.b/authorize",
        )

        # with app.test_request_context():
        with mock.patch("requests.sessions.Session.send") as send:
            req_scope = {"type": "http", "session": {}}
            req = Request(req_scope)
            send.return_value = mock_send_value("oauth_token=foo&oauth_verifier=baz")
            resp = client.authorize_redirect(req, "https://b.com/bar")
            self.assertEqual(resp.status_code, 307)
            url = resp.headers.get("Location")
            self.assertIn("oauth_token=foo", url)
            self.assertIsNotNone(req.session.get("_dev_authlib_req_token_"))

        with mock.patch("requests.sessions.Session.send") as send:
            send.return_value = mock_send_value("oauth_token=a&oauth_token_secret=b")
            token = client.authorize_access_token(req)
            self.assertEqual(token["oauth_token"], "a")

    def test_oauth2_authorize(self):
        app = App()
        app.add_middleware(SessionMiddleware, secret_key="xxxxx")
        oauth = OAuth()
        client = oauth.register(
            "dev",
            client_id="dev",
            client_secret="dev",
            api_base_url="https://i.b/api",
            access_token_url="https://i.b/token",
            authorize_url="https://i.b/authorize",
        )

        req_scope = {"type": "http", "session": {}}
        req = Request(req_scope)

        resp = client.authorize_redirect(req, redirect_uri="https://b.com/bar")
        self.assertEqual(resp.status_code, 307)

        url = resp.headers.get("Location")
        self.assertIn("state=", url)

        state = req.session["_dev_authlib_state_"]
        self.assertIsNotNone(state)

        with mock.patch("requests.sessions.Session.send") as send:
            send.return_value = mock_send_value(get_bearer_token())
            req_scope.update(
                {
                    "path": "/",
                    "query_string": "code=a&state={}".format(state).encode(),
                    "session": req.session,
                }
            )
            req = Request(req_scope)
            token = client.authorize_access_token(req)
            self.assertEqual(token["access_token"], "a")

    def test_oauth2_authorize_code_challenge(self):
        app = App()
        app.add_middleware(SessionMiddleware, secret_key="xxxxx")
        oauth = OAuth()
        client = oauth.register(
            "dev",
            client_id="dev",
            api_base_url="https://i.b/api",
            access_token_url="https://i.b/token",
            authorize_url="https://i.b/authorize",
            client_kwargs={"code_challenge_method": "S256"},
        )

        req_scope = {"type": "http", "session": {}}
        req = Request(req_scope)

        resp = client.authorize_redirect(req, redirect_uri="https://b.com/bar")
        self.assertEqual(resp.status_code, 307)

        url = resp.headers.get("Location")
        self.assertIn("code_challenge=", url)
        self.assertIn("code_challenge_method=S256", url)

        state = req.session["_dev_authlib_state_"]
        self.assertIsNotNone(state)

        verifier = req.session["_dev_authlib_code_verifier_"]
        self.assertIsNotNone(verifier)

        def fake_send(sess, req, **kwargs):
            self.assertIn("code_verifier={}".format(verifier), req.body)
            return mock_send_value(get_bearer_token())

        req_scope.update(
            {
                "path": "/",
                "query_string": "code=a&state={}".format(state).encode(),
                "session": req.session,
            }
        )
        req = Request(req_scope)

        with mock.patch("requests.sessions.Session.send", fake_send):
            token = client.authorize_access_token(req)
            self.assertEqual(token["access_token"], "a")

    def test_with_fetch_token_in_register(self):
        def fetch_token(request):
            return {"access_token": "dev", "token_type": "bearer"}

        oauth = OAuth()
        client = oauth.register(
            "dev",
            client_id="dev",
            client_secret="dev",
            api_base_url="https://i.b/api",
            access_token_url="https://i.b/token",
            authorize_url="https://i.b/authorize",
            fetch_token=fetch_token,
        )

        def fake_send(sess, req, **kwargs):
            self.assertEqual(sess.token["access_token"], "dev")
            return mock_send_value(get_bearer_token())

        with mock.patch("requests.sessions.Session.send", fake_send):
            req_scope = {"type": "http", "session": {}}
            req = Request(req_scope)
            client.get("/user", request=req)

    def test_with_fetch_token_in_oauth(self):
        def fetch_token(name, request):
            return {"access_token": name, "token_type": "bearer"}

        oauth = OAuth(fetch_token)
        client = oauth.register(
            "dev",
            client_id="dev",
            client_secret="dev",
            api_base_url="https://i.b/api",
            access_token_url="https://i.b/token",
            authorize_url="https://i.b/authorize",
        )

        def fake_send(sess, req, **kwargs):
            self.assertEqual(sess.token["access_token"], "dev")
            return mock_send_value(get_bearer_token())

        with mock.patch("requests.sessions.Session.send", fake_send):
            req_scope = {"type": "http", "session": {}}
            req = Request(req_scope)
            client.get("/user", request=req)

    def test_access_token_with_fetch_token(self):
        app = App()
        app.add_middleware(SessionMiddleware, secret_key="xxxxx")
        oauth = OAuth()
        token = get_bearer_token()
        client = oauth.register(
            "dev",
            client_id="dev",
            client_secret="dev",
            api_base_url="https://i.b/api",
            access_token_url="https://i.b/token",
            authorize_url="https://i.b/authorize",
            fetch_token=lambda name: token,
        )

        def fake_send(sess, req, **kwargs):
            auth = req.headers["Authorization"]
            self.assertEqual(auth, "Bearer {}".format(token["access_token"]))
            resp = mock.MagicMock()
            resp.text = "hi"
            resp.status_code = 200
            return resp

        with mock.patch("requests.sessions.Session.send", fake_send):
            req_scope = {"type": "http", "session": {}}
            req = Request(req_scope)
            resp = client.get("/api/user", request=req)
            self.assertEqual(resp.text, "hi")

            # trigger ctx.authlib_client_oauth_token
            resp = client.get("/api/user", request=req)
            self.assertEqual(resp.text, "hi")

    def test_request_with_refresh_token(self):
        app = App()
        app.add_middleware(SessionMiddleware, secret_key="xxxxx")
        oauth = OAuth()

        expired_token = {
            "token_type": "Bearer",
            "access_token": "expired-a",
            "refresh_token": "expired-b",
            "expires_in": "3600",
            "expires_at": 1566465749,
        }
        client = oauth.register(
            "dev",
            client_id="dev",
            client_secret="dev",
            api_base_url="https://i.b/api",
            access_token_url="https://i.b/token",
            refresh_token_url="https://i.b/token",
            authorize_url="https://i.b/authorize",
            fetch_token=lambda name: expired_token,
        )

        def fake_send(sess, req, **kwargs):
            if req.url == "https://i.b/token":
                auth = req.headers["Authorization"]
                self.assertIn("Basic", auth)
                resp = mock.MagicMock()
                resp.json = get_bearer_token
                resp.status_code = 200
                return resp

            resp = mock.MagicMock()
            resp.text = "hi"
            resp.status_code = 200
            return resp

        with mock.patch("requests.sessions.Session.send", fake_send):
            resp = client.get("/api/user", token=expired_token)
            self.assertEqual(resp.text, "hi")

    def test_request_withhold_token(self):
        app = App()
        app.add_middleware(SessionMiddleware, secret_key="xxxxx")
        oauth = OAuth()
        client = oauth.register(
            "dev",
            client_id="dev",
            client_secret="dev",
            api_base_url="https://i.b/api",
            access_token_url="https://i.b/token",
            authorize_url="https://i.b/authorize",
        )

        def fake_send(sess, req, **kwargs):
            auth = req.headers.get("Authorization")
            self.assertIsNone(auth)
            resp = mock.MagicMock()
            resp.text = "hi"
            resp.status_code = 200
            return resp

        with mock.patch("requests.sessions.Session.send", fake_send):
            resp = client.get("/api/user", withhold_token=True)
            self.assertEqual(resp.text, "hi")
