#!/usr/bin/python3
# coding: utf-8

'''reboot hosts'''
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

import logging
import sys

try:
    from fabric import task
except ImportError:
    sys.stderr.write('cannot find fabric, install with `apt install python3-fabric`')  # noqa: E501
    raise
# no check required, fabric depends on invoke
import invoke


@task
def getmaster(con, hide=True):
    '''find master ganeti

    This can be used to detect if a node is running ganeti or note.'''
    master = False
    logging.info('checking for ganeti master on node %s', con.host)
    result = con.run('gnt-cluster getmaster',
                     hide=hide, dry=False, warn=True)
    if result.ok:
        master = result.stdout.strip()
        logging.info('ganeti node detected with master %s', master)
        return master
    raise invoke.exceptions.Failure(result,
                                    '%s is not a ganeti node' % con.host)


@task
def empty_node(con, node):
    '''migrate primary instances

    This migrates (using gnt-node migrate) *primary* instances away
    from this node, towards their secondary node. This is generally
    done in preperation for a reboot.

    This is *not* sufficient to retire a node, for that a full
    "evacuation" (including secondary nodes) needs to be performed.
    '''
    command = 'gnt-node migrate -f %s' % node
    logging.info('sending command %s to node %s', command, con.host)
    result = con.run(command, warn=True)
    # TODO: failover master?
    return (result.ok
            and (
                "All instances migrated successfully." in result.stdout
                or ("No primary instances on node %s, exiting." % con.host) in result.stdout  # noqa: E501
            )
    )
