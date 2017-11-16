from __future__ import unicode_literals, print_function
import time
import requests
import mock


def mock_json_response(payload):
    def fake_send(r, **kwargs):
        resp = mock.MagicMock()
        resp.json = lambda: payload
        return resp
    return fake_send


def mock_text_response(body, status_code=200):
    def fake_send(r, **kwargs):
        resp = mock.MagicMock(spec=requests.Response)
        resp.cookies = []
        resp.text = body
        resp.status_code = status_code
        return resp
    return fake_send


def get_bearer_token():
    return {
        'token_type': 'Bearer',
        'access_token': 'a',
        'refresh_token': 'b',
        'expires_in': '3600',
        'expires_at': int(time.time()) + 3600,
    }
