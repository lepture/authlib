import json
import time
from ..base_client import FrameworkIntegration


class StartletteIntegration(FrameworkIntegration):
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
        else:
            value = session.get(key)
        if value:
            return value.get('data')
        return None

    async def set_state_data(self, session, state, data):
        key = f'_state_{self.name}_{state}'
        if self.cache:
            await self.cache.set(key, {'data': data}, self.expires_in)
        else:
            now = time.time()
            session[key] = {'data': data, 'exp': now + self.expires_in}

    async def clear_state_data(self, session, state):
        key = f'_state_{self.name}_{state}'
        if self.cache:
            await self.cache.delete(key)
        else:
            session.pop(key, None)
            self._clear_session_state(session)

    def update_token(self, token, refresh_token=None, access_token=None):
        pass

    @staticmethod
    def load_config(oauth, name, params):
        if not oauth.config:
            return {}

        rv = {}
        for k in params:
            conf_key = '{}_{}'.format(name, k).upper()
            v = oauth.config.get(conf_key, default=None)
            if v is not None:
                rv[k] = v
        return rv
