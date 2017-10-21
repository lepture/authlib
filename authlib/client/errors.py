from requests.compat import is_py3


class OAuthException(RuntimeError):
    def __init__(self, message, type=None, data=None):
        self.message = message
        self.type = type
        self.data = data

    def __str__(self):
        if is_py3:
            return self.message
        return self.message.encode('utf-8')

    def __unicode__(self):
        return self.message
