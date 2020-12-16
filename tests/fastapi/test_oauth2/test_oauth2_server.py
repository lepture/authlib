from authlib.integrations.fastapi_oauth2 import ResourceProtector
from authlib.integrations.sqla_oauth2 import create_bearer_token_validator
from fastapi import Request

from .models import Client, Token, User, db
from .oauth2_server import TestCase, create_authorization_server

require_oauth = ResourceProtector()
BearerTokenValidator = create_bearer_token_validator(db, Token)
require_oauth.register_token_validator(BearerTokenValidator())


def create_resource_server(app):
    @app.get("/user")
    @require_oauth(["profile"])
    def user_profile(request: Request):
        user = request.state.token.user
        return {"id": user.id, "username": user.username}

    @app.get("/user/email")
    @require_oauth("email")
    def user_email(request: Request):
        pass

    @app.get("/info")
    @require_oauth()
    def public_info(request: Request):
        return {"status": "ok"}

    @app.get("/operator-and")
    @require_oauth(["profile email"])
    def operator_and(request: Request):
        return {"status": "ok"}

    @app.get("/operator-or")
    @require_oauth(["profile", "email"])
    def operator_or(request: Request):
        return {"status": "ok"}

    @app.get("/acquire")
    def test_acquire(request: Request):
        with require_oauth.acquire(request, ["profile"]) as token:
            user = token.user
            return {"id": user.id, "username": user.username}


class AuthorizationTest(TestCase):
    def test_none_grant(self):
        create_authorization_server(self.app)
        authorize_url = (
            "/oauth/authorize?response_type=token" "&client_id=implicit-client"
        )
        rv = self.client.get(authorize_url)
        self.assertIn("unsupported_response_type", rv.text)

        rv = self.client.post(authorize_url, data={"user_id": "1"})
        self.assertNotEqual(rv.status_code, 200)

        rv = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": "x",
            },
        )
        data = rv.json()
        self.assertEqual(data["error"], "unsupported_grant_type")


class ResourceTest(TestCase):
    def prepare_data(self):
        create_resource_server(self.app)

        user = User(username="foo")
        db.add(user)
        db.commit()
        client = Client(
            user_id=user.id,
            client_id="resource-client",
            client_secret="resource-secret",
        )
        client.set_client_metadata(
            {
                "scope": "profile",
                "redirect_uris": ["http://localhost/authorized"],
            }
        )
        db.add(client)
        db.commit()

    def create_token(self, expires_in=3600):
        token = Token(
            user_id=1,
            client_id="resource-client",
            token_type="bearer",
            access_token="a1",
            scope="profile",
            expires_in=expires_in,
        )
        db.add(token)
        db.commit()

    def create_bearer_header(self, token):
        return {"Authorization": "Bearer " + token}

    def test_invalid_token(self):
        self.prepare_data()

        rv = self.client.get("/user")
        self.assertEqual(rv.status_code, 401)
        resp = rv.json()
        self.assertEqual(resp["detail"]["error"], "missing_authorization")

        headers = {"Authorization": "invalid token"}
        rv = self.client.get("/user", headers=headers)
        self.assertEqual(rv.status_code, 401)
        resp = rv.json()
        self.assertEqual(resp["detail"]["error"], "unsupported_token_type")

        headers = self.create_bearer_header("invalid")
        rv = self.client.get("/user", headers=headers)
        self.assertEqual(rv.status_code, 401)
        resp = rv.json()
        self.assertEqual(resp["detail"]["error"], "invalid_token")

    def test_expired_token(self):
        self.prepare_data()
        self.create_token(-10)
        headers = self.create_bearer_header("a1")

        rv = self.client.get("/user", headers=headers)
        self.assertEqual(rv.status_code, 401)
        resp = rv.json()
        self.assertEqual(resp["detail"]["error"], "invalid_token")

        rv = self.client.get("/acquire", headers=headers)
        self.assertEqual(rv.status_code, 401)

    def test_insufficient_token(self):
        self.prepare_data()
        self.create_token()
        headers = self.create_bearer_header("a1")
        rv = self.client.get("/user/email", headers=headers)
        self.assertEqual(rv.status_code, 403)
        resp = rv.json()
        self.assertEqual(resp["detail"]["error"], "insufficient_scope")

    def test_access_resource(self):
        self.prepare_data()
        self.create_token()
        headers = self.create_bearer_header("a1")

        rv = self.client.get("/user", headers=headers)
        resp = rv.json()
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(resp["username"], "foo")

        rv = self.client.get("/acquire", headers=headers)
        resp = rv.json()
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(resp["username"], "foo")

        rv = self.client.get("/info", headers=headers)
        resp = rv.json()
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(resp["status"], "ok")

    def test_scope_operator(self):
        self.prepare_data()
        self.create_token()
        headers = self.create_bearer_header("a1")
        rv = self.client.get("/operator-and", headers=headers)
        self.assertEqual(rv.status_code, 403)
        resp = rv.json()
        self.assertEqual(resp["detail"]["error"], "insufficient_scope")

        rv = self.client.get("/operator-or", headers=headers)
        self.assertEqual(rv.status_code, 200)
