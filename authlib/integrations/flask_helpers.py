from flask import request as flask_req
from authlib.common.encoding import to_unicode


def create_oauth_request(request, request_cls, use_json=False):
    if isinstance(request, request_cls):
        return request

    if not request:
        request = flask_req

    if request.method == 'POST':
        if use_json:
            body = request.get_json()
        else:
            body = request.form.to_dict(flat=True)
    else:
        body = None

    # query string in werkzeug Request.url is very weird
    # scope=profile%20email will be scope=profile email
    url = request.base_url
    if request.query_string:
        url = url + '?' + to_unicode(request.query_string)
    return request_cls(request.method, url, body, request.headers)
