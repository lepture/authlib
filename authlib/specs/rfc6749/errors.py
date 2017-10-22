
class OAuth2Error(Exception):
    error = None
    status_code = 400
    description = ''

    def __init__(self, description=None, status_code=None,
                 uri=None, state=None, realm=None):
        if description is not None:
            self.description = description

        message = '%s: %s' % (self.error, self.description)
        super(OAuth2Error, self).__init__(message)

        if status_code is not None:
            self.status_code = status_code

        self.uri = uri
        self.state = state
        self.realm = realm

    def __str__(self):
        return '{} {}: {}'.format(
            self.status_code,
            self.error,
            self.description
        )

    def __repr__(self):
        return "<{} '{}: {}'>".format(
            self.__class__.__name__,
            self.status_code,
            self.error
        )

    def get_body(self):
        """Get a list of body."""
        error = [('error', self.error)]
        if self.description:
            error.append(('error_description', self.description))
        if self.uri:
            error.append(('error_uri', self.uri))
        if self.state:
            error.append(('state', self.state))
        return error

    def get_headers(self):
        """Get a list of headers."""
        return [
            ('Content-Type', 'application/json'),
            ('Cache-Control', 'no-store'),
            ('Pragma', 'no-cache')
        ]
