
class OAuth2Error(Exception):
    error = None
    status_code = 400
    description = ''

    def __init__(self, description=None, status_code=None, realm=None):
        if description is not None:
            self.description = description
        if status_code is not None:
            self.status_code = status_code
        self.realm = realm
        message = '(%s) %s' % (self.error, self.description)
        super(OAuth2Error, self).__init__(message)
