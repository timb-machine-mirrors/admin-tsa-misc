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

from enum import Enum
from contextlib import closing
import logging
import socket
import sys
import time

try:
    from fabric import task
except ImportError:
    sys.stderr.write('cannot find fabric, install with `apt install python3-fabric`')  # noqa: E501
    raise
# no check required, fabric depends on invoke
import invoke
import paramiko.ssh_exception


from . import ganeti
from . import host

DEFAULT_DELAY_DOWN = 30  # in seconds
DEFAULT_DELAY_UP = 300  # in seconds
DEFAULT_DELAY_HOSTS = 120  # in seconds
DEFAULT_DELAY_SHUTDOWN = 10  # in minutes
DEFAULT_REASON = 'no reason given'


@task
def wait_for_shutdown(con, wait_timeout=DEFAULT_DELAY_DOWN, wait_confirm=3):
    '''wait for host to shutdown

    This pings the host and waits one second until timeout is expired
    or until it stops pinging.

    Returns True if the box stops pinging before timeout, or False if
    the box still pings after the timeout expired.
    '''
    confirmations = 0
    for i in range(wait_timeout):
        if tcp_ping_host(con):
            # port is open, so we didn't timeout, sleep the required delay
            # TODO: discount the ping time to get a real one second delay?
            time.sleep(1)
        else:
            if confirmations >= wait_confirm:
                break
            else:
                confirmations += 1
    return confirmations >= wait_confirm


@task
def wait_for_boot(con, timeout=DEFAULT_DELAY_UP):
    '''wait for host to ping

    This tries to ping the host until it responds or until the timeout
    expires.

    This returns true if the host pings or False if the timeout
    expires and the host still does not ping.
    '''
    for i in range(timeout):
        # this will "sleep" one second if host is unreachable
        if tcp_ping_host(con):
            return True
    return tcp_ping_host(con)


class ShutdownType(str, Enum):
    '''the different flags that can be passed to the shutdown command

    This is not called "Flag" because that has a specific meaning for
    Enum classes, specifically stuff that can be combined with bitwise
    operators.
    '''
    reboot = '-r'
    halt = '-h'
    wall = '-k'
    cancel = '-c'

    def __str__(self):
        '''return the actual string representation

        the default string representation of an Enum is Class.field,
        not the actual value's representation. so instead of returning
        (say) 'ShutdownType.reboot', we return '-r' here.
        '''
        return self.value


@task
def shutdown(con,
             kind=ShutdownType.reboot,
             reason=DEFAULT_REASON,
             delay=DEFAULT_DELAY_SHUTDOWN):
    '''trigger a shutdown or reboot on the host'''
    return con.run('shutdown %s +%d "%s"' % (kind, delay, reason))


# https://github.com/fabric/fabric/issues/2061
# TODO: replace OSError by this everywhere?
class FabricException(OSError, paramiko.ssh_exception.SSHException):
    pass


# TODO: make shutdown type customizable?
@task
def reboot_and_wait(con,
                    reason=DEFAULT_REASON,
                    delay_shutdown=DEFAULT_DELAY_SHUTDOWN,
                    delay_down=DEFAULT_DELAY_DOWN,
                    delay_up=DEFAULT_DELAY_UP):
    '''shutdown the machine and wait for the box to return'''
    # TODO: check if reboot required
    # TODO: check reboot policy, especially for reboot delays
    try:
        master = ganeti.getmaster(con)
    except invoke.exceptions.Failure:
        logging.info('host %s is not a ganeti node', con.host)
    else:
        master_con = host.find_context(master, config=con.config)

        # shorter delay, as the node will be empty
        delay_shutdown = 0
        logging.info('ganeti node detected, migrating instances from  %s',
                     con.host)
        if not ganeti.empty_node(con, master_con):
            logging.error('failed to empty node %s, aborting', con.host)
            return False

    try:
        shutdown(con, ShutdownType.reboot, reason, delay_shutdown)
    except invoke.UnexpectedExit as e:
        logging.error('unexpected error issuing reboot on %s: %s', con.host, e)
        return False
    except FabricException as e:
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
    try:
        con.run('uptime')
    except FabricException as e:
        logging.error('host %s cannot be reached by fabric: ', con.host, e)
        return False

    return True


@task
def tcp_ping_host(con, port=22, timeout=1):
    '''ping the host by opening a TCP socket

    This is implemented using TCP because ICMP pings require raw
    sockets and so root access or ICMP capabilities. Besides, "ping"
    doesn't really tell us if a host has returned: what we want to
    know is if *services* are running and for that, TCP is a better
    model.

    The *port* argument determines which port is open (22 by default,
    since it's commonly available on all our hosts). The *timeout*
    argument determines how long we wait for a response (default: one
    second).
    '''

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
