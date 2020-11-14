from authlib.common.encoding import json_dumps


class KeySet(object):
    """This class represents a JSON Web Key Set."""

    def __init__(self, keys):
        self.keys = keys

    def as_dict(self, is_private=False):
        """Represent this key as a dict of the JSON Web Key Set."""
        return {'keys': [k.as_dict(is_private) for k in self.keys]}

    def as_json(self, is_private=False):
        """Represent this key set as a JSON string."""
        obj = self.as_dict(is_private)
        return json_dumps(obj)

    def find_by_kid(self, kid):
        """Find the key matches the given kid value.

        :param kid: A string of kid
        :return: Key instance
        :raise: ValueError
        """
        for k in self.keys:
            if k.tokens.get('kid') == kid:
                return k
        raise ValueError('Invalid JSON Web Key Set')
