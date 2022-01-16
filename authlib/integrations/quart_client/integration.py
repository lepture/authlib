import json
import time

from quart import current_app
from quart.signals import Namespace
from ..base_client import FrameworkIntegration

_signal = Namespace()
#: signal when token is updated
token_update = _signal.signal('token_update')


class QuartIntegration(FrameworkIntegration):
    async def _get_cache_data(self, key):
        value = await self.cache.get(key)
        if not value:
            return None
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            return None

    async def get_state_data(self, session, state):
        key = f'_state_{self.name}_{state}'
        if self.cache:
            value = await self._get_cache_data(key)
        elif session is not None:
            value = session.get(key)
        else:
            value = {}
        return value.get('data', {})

    async def set_state_data(self, session, state, data):
        key = f'_state_{self.name}_{state}'
        if self.cache:
            await self.cache.set(key, {'data': data}, self.expires_in)
        elif session is not None:
            now = time.time()
            session[key] = {'data': data, 'exp': now + self.expires_in}

    async def clear_state_data(self, session, state):
        key = f'_state_{self.name}_{state}'
        if self.cache:
            await self.cache.delete(key)
        elif session is not None:
            session.pop(key, None)
            self._clear_session_state(session)

    def update_token(self, token, refresh_token=None, access_token=None):
        token_update.send(
            current_app,
            name=self.name,
            token=token,
            refresh_token=refresh_token,
            access_token=access_token,
        )

    @staticmethod
    def load_config(oauth, name, params):
        rv = {}
        for k in params:
            conf_key = '{}_{}'.format(name, k).upper()
            v = oauth.app.config.get(conf_key, None)
            if v is not None:
                rv[k] = v
        return rv
