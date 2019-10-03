# flake8: noqa

from authlib.integrations.sqla_oauth1 import *
from authlib.deprecate import deprecate

deprecate('Deprecate "authlib.flask.oauth1.sqla", USE "authlib.integrations.sqla_oauth1" instead', '1.0', 'Jeclj', 'sq')
