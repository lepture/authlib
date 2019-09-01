import os
import base64
from authlib.common.encoding import to_bytes, to_unicode
from authlib.django.oauth2 import AuthorizationServer
from .models import Client, OAuth2Token
from ..base import TestCase as _TestCase


os.environ['AUTHLIB_INSECURE_TRANSPORT'] = 'true'


class TestCase(_TestCase):
    def create_server(self):
        return AuthorizationServer(Client, OAuth2Token)

    def create_basic_auth(self, username, password):
        text = '{}:{}'.format(username, password)
        auth = to_unicode(base64.b64encode(to_bytes(text)))
        return 'Basic ' + auth
