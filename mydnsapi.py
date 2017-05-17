import requests
import requests.auth
import urllib.parse


def authenticated(method):
    """Decorator that checks that an authenticator has been supplied. Returns None otherwise."""
    def wrapper(*args):
        return method(*args) if args[0].has_auth() else None
    return wrapper


class MyDNSHostAPI:

    def __init__(self, base_url=None, auth=None):
        self.__base_url = base_url or 'https://api.mydnshost.co.uk/'
        self.__version = '1.0'
        self.__auth = auth
        self.__domain_admin = False

    def set_auth(self, auth: requests.auth.AuthBase):
        self.__auth = auth

    def has_auth(self):
        return self.__auth is not None

    def valid_auth(self):
        return self.get_user_data() is not None

    def use_domain_admin(self, domain_admin):
        self.__domain_admin = domain_admin

    @authenticated
    def get_user_data(self):
        return self.__get('userdata').get('response')

    @authenticated
    def get_users(self):
        return self.__get('users').get('response')

    @authenticated
    def get_user_info(self, user_id='self'):
        return self.__get('users/%s' % user_id).get('response')

    @authenticated
    def set_user_info(self, data, user_id='self'):
        return self.__post('users/%s' % user_id, data).get('response')

    @authenticated
    def create_user(self, data):
        return self.__post('users/create', data)

    @authenticated
    def delete_user(self, user_id):
        return self.__delete('users/%s' % user_id)

    @authenticated
    def get_api_keys(self):
        return self.__get('users/self/keys').get('response')

    @authenticated
    def create_api_key(self, data):
        return self.__post('users/self/keys', data)

    @authenticated
    def update_api_key(self, key, data):
        return self.__post('users/self/keys/%s' % key, data)

    @authenticated
    def delete_api_key(self, key):
        return self.__delete('users/self/keys/%s' % key)

    @authenticated
    def get_session_id(self):
        return (self.__get('session').get('response') or {}).get('session')

    # TODO: Wrap the requests calls and handle API errors.
    # TODO: Return just the 'response' value instead of all the callers doing it.
    def __get(self, api_method):
        return requests.get(self.__build_url(api_method), auth=self.__auth).json()

    def __post(self, api_method, data):
        return requests.post(self.__build_url(api_method), json={'data': data}, auth=self.__auth).json()

    def __delete(self, api_method):
        return requests.delete(self.__build_url(api_method), auth=self.__auth).json()

    def __build_url(self, api_method):
        admin_prefix = 'admin/' if self.__domain_admin and api_method.startswith('domain') else ''
        return urllib.parse.urljoin(self.__base_url, '%s%s/%s' % (admin_prefix, self.__version, api_method))


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
