#!/usr/bin/python3
# coding: utf-8

'''KVM/libvirt to Ganeti migration script'''
# Copyright (C) 2020 Antoine Beaupré <anarcat@debian.org>
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
    from fabric import Connection
except ImportError:
    sys.stderr.write('cannot find fabric, install with `apt install python3-fabric`')  # noqa: E501
    raise


from . import ganeti


def parse_args(args=sys.argv[1:]):
    parser = argparse.ArgumentParser(description=__doc__,
                                     epilog='''migrate a KVM instance to the Ganeti cluster''')  # noqa: E501
    parser.add_argument('--verbose', '-v', dest='log_level',
                        action='store_const', const='info', default='warning')
    parser.add_argument('--debug', '-d', dest='log_level',
                        action='store_const', const='debug', default='warning')
    parser.add_argument('--dryrun', '-n', action='store_true',
                        help='do nothing')
    parser.add_argument('--kvm-host', required=True,
                        help='host to migrate the instance from')
    parser.add_argument('--ganeti-master',
                        help='ganeti master node')
    parser.add_argument('--ganeti-node',
                        help='spare ganeti node to migrate the instance to')
    parser.add_argument('--instance', required=True,
                        help='host to migrate')
    return parser.parse_args(args=args)


def main(args):
    kvm_con = Connection(args.kvm_host)
    ganeti.libvirt_import(kvm_con, args.ganeti_node, args.instance)


if __name__ == '__main__':
    args = parse_args()
    logging.basicConfig(format='%(message)s', level=args.log_level.upper())
    # override default logging policies in submodules
    #
    # without this, we get debugging info from paramiko with --verbose
    for mod in 'fabric', 'paramiko', 'invoke':
        logging.getLogger(mod).setLevel('WARNING')
    main(args)
