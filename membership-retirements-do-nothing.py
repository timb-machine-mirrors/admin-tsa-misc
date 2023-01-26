#!/usr/bin/env python

# this is a do-nothing script to aid (and eventually automate) membership/account retirements
# https://blog.danslimmon.com/2019/07/15/do-nothing-scripting-the-key-to-gradual-automation/

import sys

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
        print("run:\n\tcumin -p 30 -b 3 '*' 'find / -user {} || true'"
              .format(context['username'], context['username']))
        print('then change ownership of any files')
        wait()

class RevokeServiceAccessStep:
    def run(self, context):
        print('check the service list: <https://gitlab.torproject.org/tpo/tpa/team/-/wikis/service>')
        print('pay special attention to the "auth" field. then revoke access to any services that'
              ' the user might have access to')
        wait()


if __name__ == "__main__":
    context = {"username": sys.argv[1]}
    procedure = [
        LockAccountStep(),
        CheckFileOwnershipStep(),
        RevokeServiceAccessStep(),
    ]
    for step in procedure:
        step.run(context)
    print('done')
