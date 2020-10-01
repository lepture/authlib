from flask import current_app, session
from flask.signals import Namespace
from ..base_client import FrameworkIntegration, OAuthError
from ..requests_client import OAuth1Session, OAuth2Session

_signal = Namespace()
#: signal when token is updated
token_update = _signal.signal('token_update')


class FlaskIntegration(FrameworkIntegration):
    oauth1_client_cls = OAuth1Session
    oauth2_client_cls = OAuth2Session

    def set_session_data(self, request, key, value):
        sess_key = '_{}_authlib_{}_'.format(self.name, key)
        session[sess_key] = value

    def get_session_data(self, request, key):
        sess_key = '_{}_authlib_{}_'.format(self.name, key)
        return session.pop(sess_key, None)

    def update_token(self, token, refresh_token=None, access_token=None):
        token_update.send(
            current_app,
            name=self.name,
            token=token,
            refresh_token=refresh_token,
            access_token=access_token,
        )

    def generate_access_token_params(self, request_token_url, request):
        if request_token_url:
            return request.args.to_dict(flat=True)

        if request.method == 'GET':
            error = request.args.get('error')
            if error:
                description = request.args.get('error_description')
                raise OAuthError(error=error, description=description)

            params = {
                'code': request.args['code'],
                'state': request.args.get('state'),
            }
        else:
            params = {
                'code': request.form['code'],
                'state': request.form.get('state'),
            }
        return params

    @staticmethod
    def load_config(oauth, name, params):
        rv = {}
        for k in params:
            conf_key = '{}_{}'.format(name, k).upper()
            v = oauth.app.config.get(conf_key, None)
            if v is not None:
                rv[k] = v
        return rv
