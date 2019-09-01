import os
from authlib.django.oauth1 import (
    CacheAuthorizationServer,
)
from .models import Client, TokenCredential
from ..base import TestCase as _TestCase

os.environ['AUTHLIB_INSECURE_TRANSPORT'] = 'true'


class TestCase(_TestCase):
    def create_server(self):
        return CacheAuthorizationServer(Client, TokenCredential)
