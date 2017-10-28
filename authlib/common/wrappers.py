
class Request(object):
    """Share the same properties of requests.Request class."""

    def __init__(self, method=None, url=None, headers=None,
                 files=None, data=None, params=None,
                 auth=None, cookies=None, json=None):

        # Default empty dicts for dict params.
        data = [] if data is None else data
        files = [] if files is None else files
        headers = {} if headers is None else headers
        params = {} if params is None else params

        self.method = method
        self.url = url
        self.headers = headers
        self.files = files
        self.data = data
        self.json = json
        self.params = params
        self.auth = auth
        self.cookies = cookies

    def __repr__(self):
        return '<Request [%s]>' % self.method
