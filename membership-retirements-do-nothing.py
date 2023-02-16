#!/usr/bin/env python

# this is a do-nothing script to aid (and eventually automate) membership/account retirements
# https://blog.danslimmon.com/2019/07/15/do-nothing-scripting-the-key-to-gradual-automation/

import sys

try:
    import pytablereader as ptr
except ImportError:
    print('the pytablereader and markdown packages are required.')
    print('run `pip install pytablereader markdown` and try again')
    exit()

__preamble = '''
./membership-retirements-do-nothing.py <username> <service_wiki_page>
'''

def wait():
    input('press enter to continue...')


class LockAccountStep:
    def run(self, context):
        context['ticket_number'] = input('enter a ticket number if relevant: ').strip()
        if context['ticket_number']:
            print('run:\n\tssh db.torproject.org ud-lock -r "{}" {}'.format(context['ticket_number'], context['username']))
        else:
            print('run:\n\tssh db.torproject.org ud-lock {}'.format(context['username']))
        wait()


class CheckFileOwnershipStep:
    def run(self, context):
        print("run:\n\tcumin -p 30 -b 5 '*' 'find / -nouser -o -nogroup || true'"
              .format(context['username'], context['username']))
        print('then change ownership of any files')
        wait()

class RevokeServiceAccessStep:
    def parse_tables(self, context):
        valid_table_headers = (
            ['service', 'purpose', 'url', 'maintainers', 'documented', 'auth'],
            ['service', 'purpose', 'url', 'maintainers', 'auth'],
        )

        table_loader = ptr.MarkdownTableFileLoader(context['service_wiki_page'])
        tables = [
            table for table in table_loader.load()
            if list(map(str.lower, table.headers)) in valid_table_headers
        ]

        by_auth = {}

        for table in tables:
            for row in table.rows:
                if row[-1].lower() in ('no', 'n/a'):
                    continue
                if by_auth.get(row[-1].lower()) is None:
                    by_auth[row[-1].lower()] = []

                by_auth[row[-1].lower()].append(row)

        for key, services in by_auth.items():
            print(f'{key}:')
            for service in services:
                print(f'\t{service[0]} - {service[3]}')

    def run(self, context):
        print("I'll parse the service tables for you. I'll show you what kind of auth a service"
              'has, and who the service maintainer is so you can contact them.')
        print("Fair warning, there's going to be a lot of output")
        wait()
        self.parse_tables(context)
        print('go through this service list, and contact relevant service maintainers about'
              'deactivating the account for ' + context['username'])
        wait()


if __name__ == '__main__':
    try:
        context = {
            'username': sys.argv[1],
            'service_wiki_page': sys.argv[2],
        }
    except IndexError:
        exit(__preamble)

    procedure = [
        LockAccountStep(),
        CheckFileOwnershipStep(),
        RevokeServiceAccessStep(),
    ]
    for step in procedure:
        step.run(context)
    print('done')
