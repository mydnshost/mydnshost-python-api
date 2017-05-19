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

    def handle_command(self, api, args):
        if args.subcommand in self.__subcommands:
            self.__subcommands[args.subcommand][1](api, args)
        else:
            self.__parser.error('Please specify a subcommand.')


class DomainsHandler(BaseHandler):

    def __init__(self):
        super().__init__({
            'list': (self.create_list_parser, self.handle_list_command),
        }, 'Modify domains associated with your account')

    def create_list_parser(self, subparsers, name):
        subparsers.add_parser(name, help='List all domains')

    def handle_list_command(self, api, _):
        print(api.get_domains())


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

    def create_add_parser(self, subparsers, name):
        parser = subparsers.add_parser(name, help='Add a new record')
        parser.add_argument('name', help='FQDN of the record to add')
        parser.add_argument('type', help='Type of the record to add')
        parser.add_argument('content', help='Content of the record to add', nargs='+')
        parser.add_argument('--ttl', help='The TTL for the record')
        parser.add_argument('--priority', help='The priority for the record')

    def create_remove_parser(self, subparsers, name):
        parser = subparsers.add_parser(name, help='Remove an existing record')
        parser.add_argument('name', help='FQDN of the record to remove')
        parser.add_argument('type', help='Type of the record to remove')
        parser.add_argument('content', help='Content of the record to remove', nargs='+')

    def handle_list_command(self, api, args):
        pass

    def handle_add_command(self, api, args):
        pass

    def handle_remove_command(self, api, args):
        pass


def get_authenticator(args, error_handler):
    if args.auth_user and args.auth_key:
        return UserKeyAuthenticator(args.auth_user, args.auth_key)
    elif 'MYDNSHOST_AUTH_USER' in os.environ and 'MYDNSHOST_AUTH_KEY' in os.environ:
        return UserKeyAuthenticator(os.environ['MYDNSHOST_AUTH_USER'], os.environ['MYDNSHOST_AUTH_KEY'])
    else:
        error_handler('No authentication method specified.')

if __name__ == '__main__':
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