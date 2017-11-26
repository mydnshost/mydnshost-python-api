import argparse
import os

from api import MyDNSHostAPI, UserKeyAuthenticator


class BaseHandler:

    def __init__(self, subcommands, help):
        self.__parser = None
        self.__subcommands = subcommands
        self.__help = help

    def create_parser(self, name, parent):
        self.__parser = parent.add_parser(name, help=self.__help)
        subparsers = self.__parser.add_subparsers(title='subcommands', dest='subcommand')
        for name, (creator, _) in self.__subcommands.items():
            creator(subparsers, name)

    def handle_command(self, api: MyDNSHostAPI, args):
        if args.subcommand in self.__subcommands:
            self.__subcommands[args.subcommand][1](api, args)
        else:
            self.__parser.error('Please specify a subcommand.')

    def find_domain(self, api: MyDNSHostAPI, subdomain):
        """
        Utility method to query the API and find the domain that contains the given subdomain.

        This is accomplished by selecting all domains that match the end of the subdomain, and then selecting the
        longest possible match.

        For example, a subdomain of 'foo.bar.example.com' may match 'bar.example.com' and 'example.com' (but wouldn't
        match 'r.example.com', as the matches must end on a separator); 'bar.example.com' is the longest, thus most
        specific, and is returned.

        Args:
            api: The API client to use to query domains
            subdomain: The name of the subdomain to find a matching domain for

        Returns:
            The best matching domain (as a string), or `None` if no domains matched.
        """
        matches = [d for d in api.get_domains().keys() if ('.%s' % subdomain).endswith('.%s' % d)]
        return next(iter(sorted(matches, key=len, reverse=True)), None)


class DomainsHandler(BaseHandler):

    def __init__(self):
        super().__init__({
            'list': (self.create_list_parser, self.handle_list_command),
        }, 'Modify domains associated with your account')

    def create_list_parser(self, subparsers, name):
        parser = subparsers.add_parser(name, help='List all domains')
        parser.add_argument('-p', '--show-permissions', action='store_true',
                            help='Show what access level you have over each domain')

    def handle_list_command(self, api: MyDNSHostAPI, args):
        for name, access in api.get_domains().items():
            if args.show_permissions:
                print('%s [%s]' % (name, access))
            else:
                print(name)


class RecordsHandler(BaseHandler):

    def __init__(self):
        super().__init__({
            'list': (self.create_list_parser, self.handle_list_command),
            'add': (self.create_add_parser, self.handle_add_command),
            'rm': (self.create_remove_parser, self.handle_remove_command),
        }, 'Modify DNS records for a domain')

    def create_list_parser(self, subparsers, name):
        parser = subparsers.add_parser(name, help='List existing records')
        parser.add_argument('name', help='Domain to list records for')
        parser.add_argument('type', help='Type of the records to list', nargs='?')
        parser.add_argument('--show-ids', action='store_true', help='Show the internal IDs of records')

    def create_add_parser(self, subparsers, name):
        parser = subparsers.add_parser(name, help='Add a new record')
        parser.add_argument('name', help='FQDN of the record to add')
        parser.add_argument('type', help='Type of the record to add')
        parser.add_argument('content', help='Content of the record to add', nargs='+')
        parser.add_argument('--ttl', help='The TTL for the record')
        parser.add_argument('--priority', help='The priority for the record')
        parser.add_argument('--show-ids', action='store_true', help='Show the internal IDs of modified records')

    def create_remove_parser(self, subparsers, name):
        parser = subparsers.add_parser(name, help='Remove an existing record')
        parser.add_argument('name', help='FQDN of the record to remove')
        parser.add_argument('type', help='Type of the record to remove', nargs='?')
        parser.add_argument('content', help='Content of the record to remove', nargs='*')

    def handle_list_command(self, api: MyDNSHostAPI, args):
        domain = self.find_domain(api, args.name)
        name = args.name[:-len(domain)].strip('.')
        records = list(self.__filter_records(api.get_domain_records(domain), name, args.type))
        self.__print_records(domain, records, args.show_ids)
        if not records:
            print('No records found.')

    def handle_add_command(self, api: MyDNSHostAPI, args):
        domain = self.find_domain(api, args.name)
        name = args.name[:-len(domain)].strip('.')
        extras = {**({'ttl': args.ttl} if args.ttl else {}), **({'priority': args.priority} if args.priority else {})}
        records = [{'name': name, 'type': args.type, 'content': c, **extras} for c in args.content]
        result = api.set_domain_records(domain, {'records': records})
        if 'changed' in result and len(result['changed']):
            print('Records created:')
            self.__print_records(domain, result['changed'], args.show_ids)
        else:
            print('No records created.')

    def handle_remove_command(self, api: MyDNSHostAPI, args):
        domain = self.find_domain(api, args.name)
        name = args.name[:-len(domain)].strip('.')
        records = [{'id': record['id'], 'delete': True} for record in
                   self.__filter_records(api.get_domain_records(domain), name, args.type, args.content)]
        result = api.set_domain_records(domain, {'records': records})
        if 'changed' in result and len(result['changed']):
            print('%s records deleted.' % len(result['changed']))
        else:
            print('No records deleted.')

    @staticmethod
    def __print_records(domain, records, show_ids=False):
        for record in records:
            name = '%s.%s' % (record['name'], domain) if len(record['name']) else domain
            print('%s%s %s %s [TTL %s]' % ('%s: ' % record['id'] if show_ids else '', name,
                                           record['type'], record['content'], record['ttl']))

    @staticmethod
    def __filter_records(records, name=None, type=None, content=None):
        """
        Filters a list of records based on their name, type or content.

        Args:
            records: The records to be filtered
            name: The name of the record to select (or `None` for any)
            type: The type of record to select (or `None` for any)
            content: A list of content values to select (or `None` for any)

        Returns:
            The input list, filtered according to the given arguments
        """
        for record in records:
            if ((not name or record['name'] == name) and
                    (not type or record['type'] == type) and
                    (not content or record['content'] in content)):
                yield record


def get_authenticator(args, error_handler):
    """
    Constructs an authenticator to use when connecting to the API.

    Preference is given to credentials passed on the command line; if none are specified then environment variables
    are checked.

    Args:
        args: The top-level command line arguments passed by the user .
        error_handler: The function to call if an error occurs (e.g. credentials not present).

    Returns:
        An authenticator object to use (unless `error_handler` was invoked).
    """
    if args.auth_user and args.auth_key:
        return UserKeyAuthenticator(args.auth_user, args.auth_key)
    elif 'MYDNSHOST_AUTH_USER' in os.environ and 'MYDNSHOST_AUTH_KEY' in os.environ:
        return UserKeyAuthenticator(os.environ['MYDNSHOST_AUTH_USER'], os.environ['MYDNSHOST_AUTH_KEY'])
    else:
        error_handler('No authentication method specified.')


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(description='Client for interacting with mydnshost.co.uk')
    parser.add_argument('--auth-key', help='API key to use to authenticate')
    parser.add_argument('--auth-user', help='Username to authenticate with')
    parser.add_argument('--base-url', default='https://api.mydnshost.co.uk/', help='Base URL to send API requests to')

    commands = {
        'domains': DomainsHandler(),
        'records': RecordsHandler(),
    }

    subparsers = parser.add_subparsers(title='subcommands', dest='command')
    for name, handler in commands.items():
        handler.create_parser(name, subparsers)

    args = parser.parse_args()
    api = MyDNSHostAPI(base_url=args.base_url, auth=get_authenticator(args, parser.error))

    if not api.valid_auth():
        parser.error('Invalid credentials')

    if args.command in commands:
        commands[args.command].handle_command(api, args)
    else:
        parser.error('Specify a command')


if __name__ == '__main__':
    main()
