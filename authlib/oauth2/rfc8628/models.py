
class DeviceCredentialMixin(object):
    def get_client_id(self):
        raise NotImplementedError()

    def get_scope(self):
        raise NotImplementedError()

    def get_user_code(self):
        raise NotImplementedError()

    def get_expires_at(self):
        raise NotImplementedError()


class DeviceCredentialDict(dict, DeviceCredentialMixin):
    def get_client_id(self):
        return self['client_id']

    def get_scope(self):
        return self.get('scope')

    def get_user_code(self):
        return self['user_code']

    def get_expires_at(self):
        return self.get('expires_at')
