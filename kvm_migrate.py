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
import io
import json
import logging
import os.path
import sys
import xml.etree.ElementTree as ET

try:
    from fabric import task, Connection
except ImportError:
    sys.stderr.write('cannot find fabric, install with `apt install python3-fabric`')  # noqa: E501
    raise

try:
    from humanize import naturalsize
except ImportError:
    sys.stderr.write('cannot import humanize, sizes will be ugly')

    def naturalsize(size, *args, **kwargs):
        return size + 'B'


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


def kvm_instance_parse_memory(xml_root):
    for tag in xml_root.findall('memory'):
        unit = tag.get('unit')
        assert unit == 'KiB'
        yield int(tag.text) * 1024


def kvm_instance_parse_cpu(xml_root):
    for tag in xml_root.findall('vcpu'):
        yield int(tag.text)


@task
def kvm_instance_fetch_libvirt_xml(kvm_con, instance):
    buffer = io.BytesIO()
    instance_config = '/etc/libvirt/qemu/%s.xml' % instance
    try:
        kvm_con.get(instance_config, local=buffer)
    except OSError as e:
        logging.error('cannot fetch instance config from %s: %s',
                      instance_config, e)
        return False
    return buffer.getvalue()


def kvm_instance_list_disks(kvm_con, instance):
    sftp = kvm_con.sftp()
    for disk in sftp.listdir_iter('/srv/vmstore/%s' % instance):
        logging.debug('found disk %s', disk.filename)
        yield '/srv/vmstore/%s/%s' % (instance, disk.filename)


def kvm_instance_disk_json(kvm_con, disk_path, hide=True):
    command = 'qemu-img info --output=json %s' % disk_path
    try:
        result = kvm_con.run(command, hide=hide)
    except OSError as e:
        logging.error('failed to run %s: %s', command, e)
        return False
    return result.stdout


def kvm_instance_swap_uuid(kvm_con, disk_path, hide=True):
    result = kvm_con.run('blkid -t TYPE=swap -s UUID -o value %s' % disk_path,
                         hide=hide)
    return result.stdout.strip()


@task
def kvm_instance_inventory(kvm_con, instance):
    inventory = {}
    logging.info('fetching instance %s inventory from %s...',
                 instance, kvm_con.host)
    xml_root = ET.fromstring(kvm_instance_fetch_libvirt_xml(kvm_con,
                                                            instance))
    # XXX: we drop duplicates in cpu and memory here
    inventory['cpu'], = list(kvm_instance_parse_cpu(xml_root))
    logging.info('CPU: %s', inventory['cpu'])
    inventory['memory'], = list(kvm_instance_parse_memory(xml_root))
    logging.info('memory: %s bytes (%s/%s)', inventory['memory'],
                 naturalsize(inventory['memory'], binary=True),
                 naturalsize(inventory['memory']))

    swap = {}
    disks = {}
    for disk in kvm_instance_list_disks(kvm_con, instance):
        j = kvm_instance_disk_json(kvm_con, disk)
        disk_info = json.loads(j)

        if disk.endswith('-swap'):
            swap_uuid = kvm_instance_swap_uuid(kvm_con, disk)
            logging.info('found swap %s: %s bytes (%s/%s) UUID:%s',
                         os.path.basename(disk),
                         disk_info['virtual-size'],
                         naturalsize(disk_info['virtual-size'], binary=True),
                         naturalsize(disk_info['virtual-size']),
                         swap_uuid)
            disk_info['swap_uuid'] = swap_uuid
            swap[disk] = disk_info
        else:
            disks[disk] = disk_info
            logging.info('disk %s: %s bytes (%s/%s)',
                         os.path.basename(disk),
                         disk_info['virtual-size'],
                         naturalsize(disk_info['virtual-size'], binary=True),
                         naturalsize(disk_info['virtual-size']))

    inventory['disks'] = disks
    return inventory


def main(args):
    kvm_con = Connection(args.kvm_host)
    kvm_instance_inventory(kvm_con, args.instance)


if __name__ == '__main__':
    args = parse_args()
    logging.basicConfig(format='%(message)s', level=args.log_level.upper())
    # override default logging policies in submodules
    #
    # without this, we get debugging info from paramiko with --verbose
    for mod in 'fabric', 'paramiko', 'invoke':
        logging.getLogger(mod).setLevel('WARNING')
    main(args)
