class JWT(object):

    def __init__(self, access_token, expires_at, refresh_token):
        self._access_token = access_token
        self._expires_at = expires_at
        self._refresh_token = refresh_token

    @property
    def access_token(self):
        return self._access_token

    @access_token.setter
    def access_token(self, value):
        self._access_token = value

    @access_token.deleter
    def access_token(self):
        del self._access_token

    @property
    def expires_at(self):
        return self._expires_at

    @expires_at.setter
    def expires_at(self, value):
        self._expires_at = value

    @expires_at.deleter
    def expires_at(self):
        del self._expires_at

    @property
    def refresh_token(self):
        return self._refresh_token

    @refresh_token.setter
    def refresh_token(self, value):
        self._refresh_token = value

    @refresh_token.deleter
    def refresh_token(self):
        del self._refresh_token
