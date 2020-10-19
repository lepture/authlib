import os
import base64
import unittest
from fastapi import FastAPI, Request, Form
from fastapi.testclient import TestClient
from authlib.common.security import generate_token
from authlib.common.encoding import to_bytes, to_unicode
from authlib.common.urls import url_encode
from authlib.integrations.sqla_oauth2 import (
    create_query_client_func,
    create_save_token_func,
)
from authlib.integrations.fastapi_oauth2 import AuthorizationServer
from authlib.oauth2 import OAuth2Error
from .models import User, Client, Token
from .database import Base, engine, db

os.environ['AUTHLIB_INSECURE_TRANSPORT'] = 'true'


def token_generator(client, grant_type, user=None, scope=None):
    token = '{}-{}'.format(client.client_id[0], grant_type)
    if user:
        token = '{}.{}'.format(token, user.get_user_id())
    return '{}.{}'.format(token, generate_token(32))


def create_authorization_server(app):
    query_client = create_query_client_func(db, Client)
    save_token = create_save_token_func(db, Token)

    server = AuthorizationServer()
    server.init_app(app, query_client, save_token)

    @app.get('/oauth/authorize')
    def authorize(request: Request):
        user_id = request.query_params.get('user_id')
        request.body = {}
        if user_id:
            end_user = db.query(User).filter(User.id == int(user_id)).first()
        else:
            end_user = None
        try:
            grant = server.validate_consent_request(request=request, end_user=end_user)
            return grant.prompt or 'ok'
        except OAuth2Error as error:
            return url_encode(error.get_body())

    @app.post('/oauth/authorize')
    def authorize(request: Request, user_id: str = Form('')):
        request.body = {}
        if user_id:
            grant_user = db.query(User).filter(User.id == int(user_id)).first()
        else:
            grant_user = None
        return server.create_authorization_response(request=request, grant_user=grant_user)

    @app.post('/oauth/token')
    def issue_token(
            request: Request,
            grant_type: str = Form(...),
            scope: str = Form(None),
            code: str = Form(None),
            refresh_token: str = Form(None),
            code_verifier: str = Form(None),
            client_id: str = Form(None),
            client_secret: str = Form(None),
            device_code: str = Form(None)):
        request.body = {
            'grant_type': grant_type,
            'scope': scope,
        }
        if grant_type == 'authorization_code':
            request.body['code'] = code
        elif grant_type == 'refresh_token':
            request.body['refresh_token'] = refresh_token

        if code_verifier:
            request.body['code_verifier'] = code_verifier

        if client_id:
            request.body['client_id'] = client_id

        if client_secret:
            request.body['client_secret'] = client_secret

        if device_code:
            request.body['device_code'] = device_code

        return server.create_token_response(request=request)

    return server


def create_fastapi_app():
    app = FastAPI()
    app.debug = True
    app.testing = True
    app.secret_key = 'testing'
    app.test_client = TestClient(app)
    app.config = {
        'OAUTH2_ERROR_URIS': [
            ('invalid_client', 'https://a.b/e#invalid_client')
        ]
    }
    return app


class TestCase(unittest.TestCase):
    def setUp(self):
        app = create_fastapi_app()

        Base.metadata.create_all(bind=engine)

        self.app = app
        self.client = app.test_client

    def tearDown(self):
        Base.metadata.drop_all(bind=engine)

    def create_basic_header(self, username, password):
        text = '{}:{}'.format(username, password)
        auth = to_unicode(base64.b64encode(to_bytes(text)))
        return {'Authorization': 'Basic ' + auth}
