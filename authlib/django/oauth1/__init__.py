# flake8: noqa

from authlib.deprecate import deprecate
from authlib.integrations.django_oauth1 import *

deprecate('Deprecate "authlib.django.oauth1", USE "authlib.integrations.django_oauth1" instead.', '1.0', 'Jeclj', 'rn')
