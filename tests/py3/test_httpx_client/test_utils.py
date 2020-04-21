import pytest

from authlib.integrations.httpx_client.utils import rebuild_request
from httpx import Headers, Request, URL
from httpx import RequestNotRead


def test_rebuild_request():
    orig = Request('GET', 'https://example.invalid')
    new = rebuild_request(orig)

    assert new is not orig

    assert new.method == orig.method
    assert new.url == orig.url
    assert new.headers == orig.headers
    assert new.stream == orig.stream
    assert new.timer.start == orig.timer.start

    with pytest.raises(RequestNotRead):
        orig.content
    with pytest.raises(RequestNotRead):
        new.content
    new.read()
    with pytest.raises(RequestNotRead):
        orig.content

    assert orig.read() == new.read()


def test_rebuild_request_changes_url():
    orig = Request('GET', 'https://example.invalid')
    url = URL('https://another.invalid')
    new = rebuild_request(orig, url=url)

    assert new.url == url


def test_rebuild_request_overwrites_header():
    headers = Headers([('X-Test', '1'), ('X-Test', '2')])
    orig = Request('GET', 'https://example.invalid', headers=headers)
    new = rebuild_request(orig, headers={'X-Test': '3'})

    assert len(new.headers.getlist('X-Test')) == 1
    assert new.headers['X-Test'] == '3'


def test_rebuild_request_data():
    data = b'Hello, world!'
    orig = Request('GET', 'https://example.invalid', data=b'')
    new = rebuild_request(orig, body=data)

    assert new.read() == data
