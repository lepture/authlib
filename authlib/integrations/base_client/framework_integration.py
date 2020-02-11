
class FrameworkIntegration(object):
    oauth1_client_cls = None
    oauth2_client_cls = None

    def __init__(self, name):
        self.name = name

    def set_session_data(self, request, key, value):
        sess_key = '_{}_authlib_{}_'.format(self.name, key)
        request.session[sess_key] = value

    def get_session_data(self, request, key):
        sess_key = '_{}_authlib_{}_'.format(self.name, key)
        return request.session.pop(sess_key, None)

    def update_token(self, token, refresh_token=None, access_token=None):
        raise NotImplementedError()

    def generate_access_token_params(self, request_token_url, request):
        raise NotImplementedError()

    @staticmethod
    def load_config(oauth, name, params):
        raise NotImplementedError()
