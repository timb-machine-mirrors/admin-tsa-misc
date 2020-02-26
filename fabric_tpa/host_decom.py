#!/usr/bin/python3
# coding: utf-8

'''decomission an instance'''
# Copyright (C) 2016 Antoine Beaupré <anarcat@debian.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import division, absolute_import
from __future__ import print_function, unicode_literals

import argparse
import logging
import sys


try:
    from fabric import task, Connection, Config
except ImportError:
    sys.stderr.write('cannot find fabric, install with `apt install python3-fabric`')  # noqa: E501
    raise
import invoke.exceptions

from .ganeti import _getmaster


__description__ = '''Part of the host retirement procedure defined at
https://help.torproject.org/tsa/howto/retire-a-host/.  Can also be
called with something like: `fab -c host_decom -H
unifolium.torproject.org --dry kvm_instance_running
test.torproject.org`.'''


def parse_args(args=sys.argv[1:]):
    parser = argparse.ArgumentParser(description=__description__,
                                     epilog=__doc__)
    parser.add_argument('--verbose', '-v', dest='log_level',
                        action='store_const', const='info', default='warning')
    parser.add_argument('--debug', '-d', dest='log_level',
                        action='store_const', const='debug', default='warning')
    parser.add_argument('--dryrun', '-n', action='store_true',
                        help='do nothing')
    parser.add_argument('--parent-host',
                        help='host the instance resides on')
    parser.add_argument('--backup-host', default='bungei.torproject.org',
                        help='host where the backups are stored (default: %(default)s)')  # noqa: E501
    parser.add_argument('--puppet-host', default='pauli.torproject.org',
                        help='puppet master host (default: %(default)s)')
    parser.add_argument('instance', nargs='+',
                        help='the instance to decomission')
    return parser.parse_args(args=args)


@task
def kvm_shutdown(kvm_con, instance):
    kvm_con.run("virsh shutdown '%s'" % instance)


@task
def kvm_undefine(kvm_con, instance):
    kvm_con.run("virsh undefine '%s'" % instance)


@task
def path_exists(host_con, path):
    logging.info('checking for path "%s" on %s', path, host_con.host)
    sftp = host_con.sftp()
    try:
        sftp.chdir(path)
    except IOError as e:
        logging.error('path %s not found: %s', path, e)
        return False
    return True


@task
def schedule_delete(host_con, path, delay):
    # TODO: shell escapes?
    command = 'rm -rf "%s"' % path
    logging.info('scheduling %s to run on %s in %s',
                 command, host_con.host, delay)
    return host_con.run("echo '%s' | at now + %s" % (command, delay),
                        warn=True).ok


@task
def kvm_instance_running(con, instance, hide=True, dry=False):
    result = con.run('virsh list --state-running --name', hide=hide, dry=dry)
    return instance in result.stdout


@task
def decom_kvm_instance(host_con, instance):
    # STEP 3
    if kvm_instance_running(host_con, instance):
        logging.info('shutting down instance %s on host %s',
                     instance, host_con.host)
        kvm_shutdown(host_con, instance)

        # TODO: wait for shutdown properly? maybe reuse the
        # shutdown procedure from the reboot system, to give
        # users a warning?
        # STEP 1?
        raise NotImplementedError("need to wait for shutdown")
    else:
        logging.info('instance %s not running, no shutdown required',
                     instance)

    # STEP 4
    logging.info('undefining instance %s on host %s',
                 instance, host_con.host)
    kvm_undefine(host_con, instance)

    logging.info('scheduling %s disk deletion on host %s',
                 instance, host_con.host)
    # TODO: lvm removal
    disk = '/srv/vmstore/%s/' % instance
    if path_exists(host_con, disk):
        schedule_delete(host_con, disk, '7 days')


@task
def decom_instance(host_con, instance):
    if host_con:
        try:
            _getmaster(host_con)
        except invoke.exceptions.Failure:
            decom_kvm_instance(host_con, instance)
        else:
            raise NotImplementedError('ganeti host decom not supported')


@task
def remove_backups(backup_con, instance):
    backup_dir = '/srv/backups/bacula/%s/' % instance
    if path_exists(backup_con, backup_dir):
        schedule_delete(backup_con, backup_dir, '30 days')


@task
def puppet_revoke(con, instance):
    con.run('puppet node clean %s' % instance)
    con.run('puppet node deactivate %s' % instance)


def main(args):
    config = Config({
        'run': {
            'dry': args.dryrun,
        }
    })
    # emulate --dry
    host_con = Connection(args.parent_host, user='root', config=config) if args.parent_host else None  # noqa: E501
    backup_con = Connection(args.backup_host, user='root', config=config) if args.backup_host else None  # noqa: E501
    puppet_con = Connection(args.puppet_host, user='root', config=config) if args.puppet_host else None  # noqa: E501

    for instance in args.instance:
        # STEP 1, 3, 4, 5
        try:
            decom_instance(host_con, instance)
        except invoke.exceptions.Failure as e:
            logging.error('failed to decomission instance %s on host %s: %s',
                          instance, host_con.host, e)
            return 1
        # STEP 13
        if backup_con:
            logging.info('scheduling %s backup disks removal on host %s',
                         instance, backup_con.host)
            try:
                remove_backups(backup_con, instance)
            except invoke.exceptions.Failure as e:
                logging.error('failed to remove %s backups on host %s: %s',
                              instance, backup_con.host, e)
                return 2
        # STEP 8
        if puppet_con:
            try:
                puppet_revoke(puppet_con, instance)
            except invoke.exceptions.Failure as e:
                logging.error('failed to revoke instance %s on host %s: %s',
                              puppet_con.host, instance, e)
                return 3
        # missing:
        # STEP 2: nagios
        # STEP 6: LDAP
        # STEP 7: DNS
        # STEP 9: Puppet source
        # STEP 10: tor-passwords
        # STEP 11: let's encrypt
        # STEP 12: DNSWL
        # STEP 14: docs
        # STEP 15: upstream decom


if __name__ == '__main__':
    args = parse_args()
    logging.basicConfig(format='%(message)s', level=args.log_level.upper())
    sys.exit(main(args))
