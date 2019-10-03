# flake8: noqa

from authlib.deprecate import deprecate
from authlib.integrations.django_oauth2 import *

deprecate('Deprecate "authlib.django.oauth2", USE "authlib.integrations.django_oauth2" instead.', '1.0', 'Jeclj', 'rn')
