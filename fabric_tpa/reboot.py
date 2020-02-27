#!/usr/bin/python3
# coding: utf-8

''''''
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
from enum import Enum
from contextlib import closing
import logging
import socket
import sys
import time

try:
    from fabric import task, Connection, Config, Result
except ImportError:
    sys.stderr.write('cannot find fabric, install with `apt install python3-fabric`')  # noqa: E501
    raise
# no check required, fabric depends on invoke
import invoke


from . import ganeti


def parse_args(args=sys.argv[1:]):
    parser = argparse.ArgumentParser(description=__doc__,
                                     epilog='''''')
    parser.add_argument('--verbose', '-v', dest='log_level',
                        action='store_const', const='info', default='warning')
    parser.add_argument('--debug', '-d', dest='log_level',
                        action='store_const', const='debug', default='warning')
    # TODO: autodetect from master list or PuppetDB
    parser.add_argument('--node', nargs='+',
                        help="node(s) to reboot")
    parser.add_argument('--dryrun', '-n', action='store_true',
                        help='do not reboot servers (but do migrate)')
    parser.add_argument('--delay-down', default=30, type=int,
                        help='how long to wait for host to shutdown (default: %(default)s seconds)')  # noqa: E501
    parser.add_argument('--delay-up', default=300, type=int,
                        help='how long to wait for host to come back up (default: %(default)s seconds)')  # noqa: E501
    parser.add_argument('--delay-nodes', default=5, type=int,
                        help='how long to wait between nodes (default: %(default)s seconds)')  # noqa: E501
    parser.add_argument('--delay-shutdown', default=10, type=int,
                        help='delay, in minutes, passed to the shutdown command (default: %(default)s minutes)')  # noqa: E501
    parser.add_argument('--reason', default='rebooting for security upgrades',
                        help='reason to give users (default: %(default)s)')
    return parser.parse_args(args=args)


@task
def wait_for_shutdown(con, timeout):
    for i in range(timeout):
        if tcp_ping_host(con):
            # port is open, so we didn't timeout, sleep the required delay
            # TODO: discount the ping time to get a real one second delay?
            time.sleep(1)
        else:
            return True
    return False


@task
def wait_for_boot(con, timeout):
    for i in range(timeout):
        # this will "sleep" one second if host is unreachable
        if tcp_ping_host(con):
            return True


class ShutdownType(str, Enum):
    reboot = '-r'
    halt = '-h'
    wall = '-k'
    cancel = '-c'


@task
def shutdown(con: Connection, kind: ShutdownType,
             reason: str, delay: str) -> Result:
    return con.run('shutdown %s +%d "%s"' % (kind, delay, reason))


@task
def reboot_and_wait(con, reason, delay_shutdown, delay_down, delay_up):
    try:
        shutdown(con, ShutdownType.reboot, reason, delay_shutdown)
    except invoke.Failure as e:
        logging.warning('failed to connect to %s, assuming down: %s',
                        con.host, e)

    # TODO: relinquish control so we schedule other jobs
    logging.info('waiting %d minutes for reboot to happen', delay_shutdown)
    # note: we convert minutes to seconds here
    time.sleep(delay_shutdown * 60)

    logging.info('waiting up to %d seconds for host to go down', delay_down)
    if not wait_for_shutdown(con, delay_down):
        logging.warning('host %s was still up after %d seconds, aborting',
                        con.host, delay_down)
        return False

    logging.info('waiting %d seconds for host to go up', delay_up)
    if not wait_for_boot(con, delay_up):
        logging.warning('host %s did not return after %d seconds, aborting',
                        con.host, delay_up)
        return False

    logging.info('host %s should be back online, checking uptime', con.host)
    if con.run('uptime', warn=True).failed:
        logging.error('host %s cannot be reached by fabric', con.host)
        return False

    return True


@task
def tcp_ping_host(con, port=22, timeout=1):
    # TODO: use fabric instead?
    try:
        with closing(socket.create_connection((con.host, port),
                                              timeout=timeout)):
            # do nothing with the socket, just test if it opens
            logging.debug('socket opened to %s:%d', con.host, port)
            return True
    except socket.timeout:
        logging.debug('timeout waiting for socket open to %s:%d',
                      con.host, port)
        return False
    except (socket.herror, socket.gaierror) as e:
        logging.error('address-related error in ping: %s', e)
        return False
    except OSError as e:
        logging.debug('connect to %s:%d failed: %s, sleeping',
                      con.host, port, e)
        time.sleep(1)
        return False

# troubleshooting:
# Fri Feb 21 16:42:18 2020  - WARNING: Can't find disk on node fsn-node-03.torproject.org  # noqa: E501
# gnt-instance activate-disks onionoo-backend-02.torproject.org


def main(args):
    config = Config({
        'run': {
            'dry': args.dryrun,
        }
    })

    for node in args.node:
        node_con = Connection(node, config=config, user='root')
        delay_shutdown = args.delay_shutdown
        # TODO: check if reboot required
        # TODO: check reboot policy, especially for reboot delays
        try:
            master = ganeti.getmaster(node_con)
        except invoke.exceptions.Failure:
            logging.info('host %s is not a ganeti node', node)
        else:
            master_con = Connection(master, config=config, user='root')

            # shorter delay, as the node will be empty
            delay_shutdown = 1
            logging.info('ganeti node detection, migrating instances from  %s',
                         node)
            if not ganeti.empty_node(master_con, node):
                logging.error('failed to empty node %s, aborting', node)
                break

        logging.info('rebooting node %s', node)
        if not reboot_and_wait(node_con,
                               reason=args.reason,
                               delay_down=args.delay_down,
                               delay_up=args.delay_up,
                               delay_shutdown=delay_shutdown):
            logging.error('rebooting node %s failed, aborting', node)
            break

        logging.info('done with node %s, sleeping %d seconds',
                     node, args.delay_nodes)
        time.sleep(args.delay_nodes)
    # TODO: rebalance ganeti cluster if nodes were migrated


if __name__ == '__main__':
    args = parse_args()
    logging.basicConfig(format='%(message)s', level=args.log_level.upper())
    # override default logging policies in submodules
    #
    # without this, we get debugging info from paramiko with --verbose
    for mod in 'fabric', 'paramiko', 'invoke':
        logging.getLogger(mod).setLevel('WARNING')
    main(args)
