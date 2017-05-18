import requests
import requests.auth
import urllib.parse
import argparse
import os


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

    def set_auth(self, auth: requests.auth.AuthBase):
        """Changes the authenticator used for future requests.

        Args:
            auth: The new authenticator to use for outgoing requests.
        """
        self.__auth = auth

    def valid_auth(self):
        """
        Performs a simple call to the API to determine if we can successfully authenticate.

        Returns:
            `True` if the call succeeded, `False` otherwise.
        """
        return self.get_user_data() is not None

    def use_domain_admin(self, domain_admin):
        """
        Sets whether or not to use admin privileges when calling domain-related methods.

        Using admin privileges allows admin clients to modify any domain regardless of their permission level.

        Args:
            domain_admin: `True` to use domain admin privileges, false otherwise.
        """
        self.__domain_admin = domain_admin

    def get_user_data(self):
        return self.__get('userdata')

    def get_users(self):
        return self.__get('users')

    def get_user_info(self, user_id='self'):
        return self.__get('users/%s' % user_id)

    def set_user_info(self, data, user_id='self'):
        return self.__post('users/%s' % user_id, data)

    def create_user(self, data):
        return self.__post('users/create', data)

    def delete_user(self, user_id):
        return self.__delete('users/%s' % user_id)

    def get_api_keys(self):
        return self.__get('users/self/keys')

    def create_api_key(self, data):
        return self.__post('users/self/keys', data)

    def update_api_key(self, key, data):
        return self.__post('users/self/keys/%s' % key, data)

    def delete_api_key(self, key):
        return self.__delete('users/self/keys/%s' % key)

    def get_session_id(self):
        return self.__get('session').get('session')

    def get_domains(self):
        return self.__get('domains')

    def create_domain(self, domain, owner=None):
        return self.__post('domains', {'domain': domain, **({'owner': owner} if owner else {})})

    def delete_domain(self, domain):
        return self.__delete('domains/%s' % domain)

    def get_domain_data(self, domain):
        return self.__get('domains/%s' % domain)

    def set_domain_data(self, domain, data):
        return self.__post('domains/%s' % domain, data)

    def get_domain_access(self, domain):
        return self.__get('domains/%s/access' % domain).get('access')

    def set_domain_access(self, domain, data):
        return self.__post('domains/%s/access' % domain, data)

    def sync_domain(self, domain):
        return self.__get('domains/%s/sync' % domain)

    def export_zone(self, domain):
        return self.__get('domains/%s/export' % domain).get('zone')

    def import_zone(self, domain, zone):
        return self.__post('domains/%s/import' % domain, {'zone': zone})

    def get_domain_records(self, domain):
        return self.__get('domains/%s/records' % domain).get('records')

    def get_domain_records_by_name(self, domain, name, r_type=None):
        return self.__get('domains/%s/records/%s%s' % (domain, name, '/%s' % r_type if r_type else '')).get('records')

    def set_domain_records(self, domain, data):
        return self.__post('domains/%s/records' % domain, data)

    def delete_domain_records(self, domain):
        return self.__delete('domains/%s/records' % domain)

    def delete_domain_records_by_name(self, domain, name, r_type=None):
        return self.__delete('domains/%s/records/%s%s' % (domain, name, '/%s' % r_type if r_type else ''))

    def __get(self, api_method):
        return self.__request('GET', api_method)

    def __post(self, api_method, data):
        return self.__request('POST', api_method, json={'data': data})

    def __delete(self, api_method):
        return self.__request('DELETE', api_method)

    def __request(self, method, api_method, **kwargs):
        if not self.__auth:
            raise MyDnsApiException('No authenticator supplied.')

        response = requests.request(method, self.__build_url(api_method), auth=self.__auth, **kwargs).json()

        if 'error' in response:
            raise MyDnsApiException(response.get('error'), response.get('errorData'))

        return response.get('response')

    def __build_url(self, api_method):
        admin_prefix = 'admin/' if self.__domain_admin and api_method.startswith('domain') else ''
        return urllib.parse.urljoin(self.__base_url, '%s%s/%s' % (admin_prefix, self.__version, api_method))


class MyDnsApiException(Exception):
    pass


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


if __name__ == '__main__':

    def get_authenticator():
        if args.auth_user and args.auth_key:
            return UserKeyAuthenticator(args.auth_user, args.auth_key)
        elif 'MYDNSHOST_AUTH_USER' in os.environ and 'MYDNSHOST_AUTH_KEY' in os.environ:
            return UserKeyAuthenticator(os.environ['MYDNSHOST_AUTH_USER'], os.environ['MYDNSHOST_AUTH_KEY'])
        else:
            parser.error('No authentication method specified.')

    parser = argparse.ArgumentParser(description='Client for interacting with mydnshost.co.uk')
    parser.add_argument('--auth-key', help='API key to use to authenticate')
    parser.add_argument('--auth-user', help='Username to authenticate with')
    parser.add_argument('--base-url', default='https://api.mydnshost.co.uk/', help='Base URL to send API requests to')

    top_sub_parsers = parser.add_subparsers(title='subcommands', dest='command')
    records_parser = top_sub_parsers.add_parser('records', help='Modify DNS records for a domain')
    apikeys_parser = top_sub_parsers.add_parser('apikeys', help='Modify API keys for your account')
    domains_parser = top_sub_parsers.add_parser('domains', help='Modify domains associated with your account')

    records_sub_parser = records_parser.add_subparsers(title='subcommands', dest='subcommand')
    records_rm_parser = records_sub_parser.add_parser('rm', help='Remove an existing record')
    records_rm_parser.add_argument('name', help='FQDN of the record to remove')
    records_rm_parser.add_argument('type', help='Type of the record to remove')
    records_rm_parser.add_argument('content', help='Content of the record to remove', nargs='+')

    records_add_parser = records_sub_parser.add_parser('add', help='Add a new record')
    records_add_parser.add_argument('name', help='FQDN of the record to add')
    records_add_parser.add_argument('type', help='Type of the record to add')
    records_add_parser.add_argument('content', help='Content of the record to add', nargs='+')
    records_add_parser.add_argument('--ttl', help='The TTL for the record')
    records_add_parser.add_argument('--priority', help='The priority for the record')

    records_list_parser = records_sub_parser.add_parser('list', help='List existing records')
    records_list_parser.add_argument('name', help='Domain to list records for')
    records_list_parser.add_argument('type', help='Type of the records to list', nargs='?')

    args = parser.parse_args()
    api = MyDNSHostAPI(base_url=args.base_url, auth=get_authenticator())

    if not api.valid_auth():
        parser.error('Invalid credentials')

    if args.command == 'records':
        pass
    elif args.command == 'apikeys':
        pass
    elif args.command == 'domains':
        pass
    else:
        parser.error('Specify a command')
