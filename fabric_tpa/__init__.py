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
def detect_ganeti(con, hide=True, fail=False):
    master = False
    logging.info('checking for ganeti master on node %s', con.host)
    result = con.run('gnt-cluster getmaster',
                     hide=hide, dry=False, warn=True)
    if result.ok:
        master = result.stdout.strip()
        logging.info('ganeti node detected with master %s', master)
        return master
    if fail:
        raise invoke.exceptions.Failure(result,
                                        '%s is not a ganeti node' % con.host)
    else:
        return False
