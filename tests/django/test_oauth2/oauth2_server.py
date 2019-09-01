import os
from authlib.django.oauth2 import AuthorizationServer
from .models import Client, OAuth2Token
from ..base import TestCase as _TestCase


os.environ['AUTHLIB_INSECURE_TRANSPORT'] = 'true'


class TestCase(_TestCase):
    def create_server(self):
        return AuthorizationServer(Client, OAuth2Token)

    def setUp(self):
        super(TestCase, self).setUp()
