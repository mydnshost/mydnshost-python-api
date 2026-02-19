import requests
import requests.auth
import urllib.parse


class MyDNSHostAPI:
    """
    API client for mydnshost.co.uk.
    """

    def __init__(self, base_url=None, auth=None):
        """Creates a new API client.

        Args:
            base_url: The base URL of the API to connect to.
            auth: The authenticator to use for outgoing requests. May be changed later with `set_auth`.
        """
        self.__base_url = base_url or 'https://api.mydnshost.co.uk/'
        self.__version = '1.0'
        self.__auth = auth
        self.__domain_admin = False
        self.__timeout = None
        self.__device_id = None
        self.__device_name = None
        self.__last_response = None

    def set_auth(self, auth: requests.auth.AuthBase):
        """Changes the authenticator used for future requests.

        Args:
            auth: The new authenticator to use for outgoing requests.
        """
        self.__auth = auth

    def set_timeout(self, timeout):
        """Sets the request timeout.

        Args:
            timeout: Timeout in seconds, or None to disable.

        Returns:
            self for chaining.
        """
        self.__timeout = timeout
        return self

    def set_device_id(self, device_id):
        """Sets the 2FA device ID to send with requests.

        Args:
            device_id: The device ID.

        Returns:
            self for chaining.
        """
        self.__device_id = device_id
        return self

    def set_device_name(self, device_name):
        """Sets the 2FA device name to save with requests.

        Args:
            device_name: The device name.

        Returns:
            self for chaining.
        """
        self.__device_name = device_name
        return self

    def use_domain_admin(self, domain_admin):
        """
        Sets whether or not to use admin privileges when calling domain-related methods.

        Using admin privileges allows admin clients to modify any domain regardless of their permission level.

        Args:
            domain_admin: `True` to use domain admin privileges, false otherwise.
        """
        self.__domain_admin = domain_admin

    def get_last_response(self):
        """Returns the last raw response dict from the API."""
        return self.__last_response

    def valid_auth(self):
        """
        Performs a simple call to the API to determine if we can successfully authenticate.

        Returns:
            `True` if the call succeeded, `False` otherwise.
        """
        return self.get_user_data() is not None

    # --- Ping / Version ---

    def ping(self, time=None):
        if time is not None:
            return self.__get('ping/%s' % time, require_auth=False)
        return self.__get('ping', require_auth=False)

    def get_version(self):
        return self.__get('version', require_auth=False)

    # --- Registration ---

    def register(self, email, name, accept_terms=False):
        return self.__post('register', {'email': email, 'realname': name, 'acceptterms': accept_terms}, require_auth=False)

    def register_confirm(self, user, code, password):
        return self.__post('register/confirm/%s' % user, {'code': code, 'password': password}, require_auth=False)

    def resend_welcome(self, user_id):
        return self.__post('users/%s/resendwelcome' % user_id, {})

    def accept_terms(self, user_id='self'):
        return self.__post('users/%s/acceptterms' % user_id, {'acceptterms': 'true'})

    # --- Password Reset ---

    def forgot_password(self, email):
        return self.__post('forgotpassword', {'email': email}, require_auth=False)

    def forgot_password_confirm(self, user, code, password):
        return self.__post('forgotpassword/confirm/%s' % user, {'code': code, 'password': password}, require_auth=False)

    # --- 2FA Push ---

    def do_auth_2fa_push(self, user, password):
        auth = UserPassAuthenticator(user, password, two_fa_push=True)
        return self.__get('session', auth_override=auth)

    # --- User Data ---

    def get_user_data(self):
        return self.__get('userdata')

    def get_users(self):
        return self.__get('users')

    # --- System Data ---

    def get_system_data_value(self, key, get_all=False):
        if not key:
            return None
        result = self.__get('system/datavalue/%s' % key)
        if get_all:
            return result
        return result.get(key) if result else None

    # --- System Stats ---

    def get_system_stats(self, stat_type, options=None):
        result = self.__get('system/stats/%s' % stat_type, params=options)
        return result.get('stats', []) if result else []

    # --- User Stats ---

    def get_user_stats(self, stat_type, options=None, user_id='self'):
        result = self.__get('users/%s/stats/%s' % (user_id, stat_type), params=options)
        return result.get('stats', []) if result else []

    # --- User Info ---

    def get_user_info(self, user_id='self'):
        return self.__get('users/%s' % user_id)

    def set_user_info(self, data, user_id='self'):
        return self.__post('users/%s' % user_id, data)

    def create_user(self, data):
        return self.__post('users/create', data)

    def delete_user(self, user_id):
        return self.__delete('users/%s' % user_id)

    def delete_user_confirm(self, user_id, confirm_code, two_factor_code=''):
        path = 'users/%s/confirm/%s' % (user_id, confirm_code)
        if two_factor_code:
            path += '/%s' % two_factor_code
        return self.__delete(path)

    # --- API Keys ---

    def get_api_keys(self, userid='self'):
        return self.__get('users/%s/keys' % userid)

    def get_api_key(self, key, userid='self'):
        return self.__get('users/%s/keys/%s' % (userid, key))

    def create_api_key(self, data, userid='self'):
        return self.__post('users/%s/keys' % userid, data)

    def update_api_key(self, key, data, userid='self'):
        return self.__post('users/%s/keys/%s' % (userid, key), data)

    def delete_api_key(self, key, userid='self'):
        return self.__delete('users/%s/keys/%s' % (userid, key))

    # --- 2FA Devices ---

    def get_2fa_devices(self, userid='self'):
        return self.__get('users/%s/2fadevices' % userid)

    def delete_2fa_device(self, device, userid='self'):
        return self.__delete('users/%s/2fadevices/%s' % (userid, device))

    # --- 2FA Keys ---

    def get_2fa_keys(self, userid='self'):
        return self.__get('users/%s/2fa' % userid)

    def get_2fa_key(self, key, userid='self'):
        return self.__get('users/%s/2fa/%s' % (userid, key))

    def create_2fa_key(self, data, userid='self'):
        return self.__post('users/%s/2fa' % userid, data)

    def update_2fa_key(self, key, data, userid='self'):
        return self.__post('users/%s/2fa/%s' % (userid, key), data)

    def verify_2fa_key(self, key, code, userid='self'):
        return self.__post('users/%s/2fa/%s/verify' % (userid, key), {'code': code})

    def delete_2fa_key(self, key, userid='self'):
        return self.__delete('users/%s/2fa/%s' % (userid, key))

    # --- Custom Data ---

    def get_custom_data_list(self, userid='self'):
        return self.__get('users/%s/customdata' % userid)

    def get_custom_data(self, key, userid='self'):
        result = self.__get('users/%s/customdata/%s' % (userid, key))
        return result.get('value') if result else None

    def set_custom_data(self, key, value, userid='self'):
        return self.__post('users/%s/customdata/%s' % (userid, key), {'value': value})

    def delete_custom_data(self, key, userid='self'):
        return self.__delete('users/%s/customdata/%s' % (userid, key))

    # --- Session / JWT ---

    def get_jwt_token(self):
        result = self.__get('session/jwt')
        return result.get('token') if result else None

    def get_session_id(self):
        return self.__get('session').get('session')

    def delete_session(self):
        return self.__delete('session')

    # --- Domains ---

    def get_domains(self, query_params=None):
        return self.__get('domains', params=query_params)

    def create_domain(self, domain, owner=None):
        return self.__post('domains', {'domain': domain, **({'owner': owner} if owner else {})})

    def delete_domain(self, domain):
        return self.__delete('domains/%s' % domain)

    def get_domain_data(self, domain):
        return self.__get('domains/%s' % domain)

    def set_domain_data(self, domain, data):
        return self.__post('domains/%s' % domain, data)

    # --- Domain Access ---

    def get_domain_access(self, domain):
        return self.__get('domains/%s/access' % domain).get('access')

    def set_domain_access(self, domain, data):
        return self.__post('domains/%s/access' % domain, data)

    # --- Domain Stats / Logs ---

    def get_domain_stats(self, domain, options=None):
        result = self.__get('domains/%s/stats' % domain, params=options)
        return result.get('stats', []) if result else []

    def get_domain_logs(self, domain, options=None):
        return self.__get('domains/%s/logs' % domain, params=options)

    # --- Domain Sync / Verify ---

    def sync_domain(self, domain):
        return self.__get('domains/%s/sync' % domain)

    def verify_domain(self, domain):
        return self.__get('domains/%s/verify' % domain)

    # --- Zone Export / Import ---

    def export_zone(self, domain, export_type=None):
        path = 'domains/%s/export' % domain
        if export_type is not None:
            path += '/%s' % export_type
        return self.__get(path).get('zone')

    def import_zone(self, domain, zone, import_type=None):
        path = 'domains/%s/import' % domain
        if import_type is not None:
            path += '/%s' % import_type
        return self.__post(path, {'zone': zone})

    # --- Domain Records ---

    def get_domain_records(self, domain):
        return self.__get('domains/%s/records' % domain).get('records')

    def get_domain_record(self, domain, record_id):
        return self.__get('domains/%s/records/%s' % (domain, record_id))

    def get_domain_records_by_name(self, domain, name, r_type=None):
        return self.__get('domains/%s/record/%s%s' % (domain, name, '/%s' % r_type if r_type else '')).get('records')

    def set_domain_records(self, domain, data):
        return self.__post('domains/%s/records' % domain, data)

    def set_domain_record(self, domain, record_id, data):
        return self.__post('domains/%s/records/%s' % (domain, record_id), data)

    def delete_domain_records(self, domain):
        return self.__delete('domains/%s/records' % domain)

    def delete_domain_record(self, domain, record_id):
        return self.__delete('domains/%s/records/%s' % (domain, record_id))

    def delete_domain_records_by_name(self, domain, name, r_type=None):
        return self.__delete('domains/%s/record/%s%s' % (domain, name, '/%s' % r_type if r_type else ''))

    # --- Domain Keys ---

    def get_domain_keys(self, domain):
        return self.__get('domains/%s/keys' % domain)

    def get_domain_key(self, domain, key):
        return self.__get('domains/%s/keys/%s' % (domain, key))

    def create_domain_key(self, domain, data):
        return self.__post('domains/%s/keys' % domain, data)

    def update_domain_key(self, domain, key, data):
        return self.__post('domains/%s/keys/%s' % (domain, key), data)

    def delete_domain_key(self, domain, key):
        return self.__delete('domains/%s/keys/%s' % (domain, key))

    # --- Domain Hooks ---

    def get_domain_hooks(self, domain):
        return self.__get('domains/%s/hooks' % domain)

    def get_domain_hook(self, domain, hook_id):
        return self.__get('domains/%s/hooks/%s' % (domain, hook_id))

    def create_domain_hook(self, domain, data):
        return self.__post('domains/%s/hooks' % domain, data)

    def update_domain_hook(self, domain, hook_id, data):
        return self.__post('domains/%s/hooks/%s' % (domain, hook_id), data)

    def delete_domain_hook(self, domain, hook_id):
        return self.__delete('domains/%s/hooks/%s' % (domain, hook_id))

    # --- Articles ---

    def get_articles(self):
        return self.__get('articles', require_auth=False)

    def get_all_articles(self):
        return self.__get('admin/articles')

    def create_article(self, data):
        return self.__post('admin/articles', data)

    def get_article(self, article_id):
        return self.__get('admin/articles/%s' % article_id)

    def update_article(self, article_id, data):
        return self.__post('admin/articles/%s' % article_id, data)

    def delete_article(self, article_id):
        return self.__delete('admin/articles/%s' % article_id)

    # --- Block Regexes ---

    def get_all_block_regexes(self):
        return self.__get('admin/blockregexes')

    def create_block_regex(self, data):
        return self.__post('admin/blockregexes', data)

    def get_block_regex(self, block_regex_id):
        return self.__get('admin/blockregexes/%s' % block_regex_id)

    def update_block_regex(self, block_regex_id, data):
        return self.__post('admin/blockregexes/%s' % block_regex_id, data)

    def delete_block_regex(self, block_regex_id):
        return self.__delete('admin/blockregexes/%s' % block_regex_id)

    # --- System Jobs ---

    def get_system_jobs(self, params=None):
        return self.__get('system/jobs/list', params=params)

    def get_system_job(self, job_id):
        return self.__get('system/jobs/%s' % job_id)

    def create_system_job(self, data):
        return self.__post('system/jobs/create', data)

    def repeat_system_job(self, job_id):
        return self.__get('system/jobs/%s/repeat' % job_id)

    def republish_system_job(self, job_id):
        return self.__get('system/jobs/%s/republish' % job_id)

    def cancel_system_job(self, job_id):
        return self.__get('system/jobs/%s/cancel' % job_id)

    def get_system_job_logs(self, job_id):
        return self.__get('system/jobs/%s/logs' % job_id)

    # --- System Services ---

    def get_system_services(self):
        return self.__get('system/service/list')

    def get_system_service_logs(self, service, params=None):
        return self.__get('system/service/%s/logs' % service, params=params)

    # --- External / ACME ---

    def httpreq_present(self, data):
        return self.__post('external/httpreq/present', data, require_auth=False)

    def httpreq_cleanup(self, data):
        return self.__post('external/httpreq/cleanup', data, require_auth=False)

    # --- Internal Helpers ---

    def __get(self, api_method, params=None, **kwargs):
        return self.__request('GET', api_method, params=params, **kwargs)

    def __post(self, api_method, data, **kwargs):
        return self.__request('POST', api_method, json={'data': data}, **kwargs)

    def __delete(self, api_method, **kwargs):
        return self.__request('DELETE', api_method, **kwargs)

    def __request(self, method, api_method, require_auth=True, auth_override=None, **kwargs):
        if require_auth and not self.__auth and auth_override is None:
            raise MyDnsApiException('No authenticator supplied.')

        auth = auth_override or self.__auth

        if self.__timeout is not None:
            kwargs.setdefault('timeout', self.__timeout)

        extra_headers = {}
        if self.__device_id is not None:
            extra_headers['X-2FA-DEVICE-ID'] = self.__device_id
        if self.__device_name is not None:
            extra_headers['X-2FA-SAVE-DEVICE'] = self.__device_name

        if extra_headers:
            existing = kwargs.get('headers', {})
            kwargs['headers'] = {**existing, **extra_headers}

        response = requests.request(method, self.__build_url(api_method), auth=auth, **kwargs).json()

        self.__last_response = response

        if 'error' in response:
            raise MyDnsApiException(response.get('error'), response.get('errorData'))

        return response.get('response')

    def __build_url(self, api_method):
        admin_prefix = 'admin/' if self.__domain_admin and api_method.startswith('domain') else ''
        return urllib.parse.urljoin(self.__base_url, '%s/%s%s' % (self.__version, admin_prefix, api_method))


class MyDnsApiException(Exception):
    def __init__(self, message, error_data=None):
        super().__init__(message)
        self.error_data = error_data


class UserPassAuthenticator(requests.auth.AuthBase):
    """Authenticator that authenticates using a username and password, with optional 2FA."""

    def __init__(self, user, password, two_fa_key=None, two_fa_push=False):
        self.__basic = requests.auth.HTTPBasicAuth(user, password)
        self.__two_fa_key = two_fa_key
        self.__two_fa_push = two_fa_push

    def __call__(self, r):
        r = self.__basic(r)
        if self.__two_fa_key:
            r.headers['X-2FA-KEY'] = self.__two_fa_key
        if self.__two_fa_push:
            r.headers['X-2FA-PUSH'] = 'true'
        return r


class UserKeyAuthenticator(requests.auth.AuthBase):
    """Authenticator that authenticates using a username and an API key."""

    def __init__(self, user, key):
        self.__user = user
        self.__key = key

    def __call__(self, r):
        r.headers['X-API-USER'] = self.__user
        r.headers['X-API-KEY'] = self.__key
        return r


class DomainKeyAuthenticator(requests.auth.AuthBase):
    """Authenticator that authenticates using a domain and domain key."""

    def __init__(self, domain, key):
        self.__domain = domain
        self.__key = key

    def __call__(self, r):
        r.headers['X-DOMAIN'] = self.__domain
        r.headers['X-DOMAIN-KEY'] = self.__key
        return r


class SessionAuthenticator(requests.auth.AuthBase):
    """Authenticator that authenticates using a session ID."""

    def __init__(self, session_id):
        self.__session_id = session_id

    def __call__(self, r):
        r.headers['X-SESSION-ID'] = self.__session_id
        return r


class JWTAuthenticator(requests.auth.AuthBase):
    """Authenticator that authenticates using a JWT token."""

    def __init__(self, token):
        self.__token = token

    def __call__(self, r):
        r.headers['Authorization'] = 'Bearer %s' % self.__token
        return r


class IdImpersonatingAuthenticator(requests.auth.AuthBase):
    """Authenticator that impersonates another user by id."""

    def __init__(self, admin_auth: requests.auth.AuthBase, user_id):
        """
        Creates a new ID-based impersonating authenticator.

        Args:
            admin_auth: The authenticator that will authenticate us as an administrator.
            user_id: The ID of the user to impersonate when making requests.
        """
        self.__admin_auth = admin_auth
        self.__user_id = user_id

    def __call__(self, r):
        r.headers['X-IMPERSONATE-ID'] = self.__user_id
        return self.__admin_auth.__call__(r)


class EmailImpersonatingAuthenticator(requests.auth.AuthBase):
    """Authenticator that impersonates another user by email."""

    def __init__(self, admin_auth: requests.auth.AuthBase, email):
        """
        Creates a new email-based impersonating authenticator.

        Args:
            admin_auth: The authenticator that will authenticate us as an administrator.
            email: The email address of the user to impersonate when making requests.
        """
        self.__admin_auth = admin_auth
        self.__email = email

    def __call__(self, r):
        r.headers['X-IMPERSONATE'] = self.__email
        return self.__admin_auth.__call__(r)
