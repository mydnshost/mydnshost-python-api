import requests
import requests.auth
import urllib.parse


class MyDNSHostAPI:

    def __init__(self, base_url=None, auth=None):
        self.__base_url = base_url or 'https://api.mydnshost.co.uk/'
        self.__version = '1.0'
        self.__auth = auth
        self.__domain_admin = False

    def set_auth(self, auth: requests.auth.AuthBase):
        self.__auth = auth

    def valid_auth(self):
        return self.get_user_data() is not None

    def get_user_data(self):
        if not self.__auth:
            return None

        result = self.__get('userdata')
        return result['response'] if 'response' in result else None

    def __get(self, api_method):
        return requests.get(self.__build_url(api_method), auth=self.__auth).json()

    def __post(self, api_method, data):
        return requests.post(self.__build_url(api_method), json={'data': data}, auth=self.__auth).json()

    def __delete(self, api_method):
        return requests.delete(self.__build_url(api_method), auth=self.__auth).json()

    def __build_url(self, api_method):
        return urllib.parse.urljoin(self.__base_url, '%s/%s' % (self.__version, api_method))


class UserKeyAuthenticator(requests.auth.AuthBase):
    """Authenticator that authenticates using a username and an API key."""

    def __init__(self, user, key):
        self.__user = user
        self.__key = key

    def __call__(self, r):
        r.headers['X-API-USER'] = self.__user
        r.headers['X-API-KEY'] = self.__key
        return r


class SessionAuthenticator(requests.auth.AuthBase):
    """Authenticator that authenticates using a session ID."""

    def __init__(self, session_id):
        self.__session_id = session_id

    def __call__(self, r):
        r.headers['X-SESSION-ID'] = self.__session_id
        return r


class IdImpersonatingAuthenticator(requests.auth.AuthBase):
    """Authenticator that impersonates another user by id."""

    def __init__(self, admin_auth: requests.auth.AuthBase, user_id):
        self.__admin_auth = admin_auth
        self.__user_id = user_id

    def __call__(self, r):
        r.headers['X-IMPERSONATE-ID'] = self.__user_id
        return self.__admin_auth.__call__(r)


class EmailImpersonatingAuthenticator(requests.auth.AuthBase):
    """Authenticator that impersonates another user by email."""

    def __init__(self, admin_auth: requests.auth.AuthBase, email):
        self.__admin_auth = admin_auth
        self.__email = email

    def __call__(self, r):
        r.headers['X-IMPERSONATE'] = self.__email
        return self.__admin_auth.__call__(r)
