#!/usr/bin/python3
# coding: utf-8

'''libvirt fabric library'''
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

from collections import OrderedDict, namedtuple
from contextlib import contextmanager
import io
import json
import logging
import os.path
import sys
import xml.etree.ElementTree as ET


try:
    from fabric import task
except ImportError:
    sys.stderr.write('cannot find fabric, install with `apt install python3-fabric`')  # noqa: E501
    raise


try:
    from humanize import naturalsize
except ImportError:
    sys.stderr.write('cannot import humanize, sizes will be ugly')

    def naturalsize(size, *args, **kwargs):
        return size + 'B'


from . import host


@task
def shutdown(con, instance):
    '''turn off instance with virsh'''
    return virsh(con, "shutdown '%s'" % instance)


@task
def undefine(con, instance):
    '''remove instance configuration file'''
    return virsh(con, "undefine '%s'" % instance)


@task
def suspend(con, instance, hide=True, dry=False):
    '''suspend an instance'''
    return virsh(con, "suspend '%s'" % instance, hide=hide, dry=dry)


@task
def resume(con, instance, hide=True, dry=False):
    '''suspend an instance'''
    return virsh(con, "resume '%s'" % instance, hide=hide, dry=dry)


@contextmanager
def suspend_then_resume(con, instance):
    try:
        yield suspend(con, instance)
    finally:
        return resume(con, instance)


@task
def is_running(con, instance, hide=True, dry=False):
    '''check if an instance is running'''
    result = virsh(con, 'list --state-running --name', hide=hide, dry=dry)
    return instance in result.stdout


@task
def virsh(con, command, hide=True, dry=False):
    '''run an arbitrary virsh command'''
    return con.run('virsh %s' % command, hide=hide, dry=dry)


@task
def retire(host_con, instance):
    '''retire a libvirt instance

    This shuts down the instance, removes the configuration and its
    disk.
    '''
    # STEP 3
    if is_running(host_con, instance):
        logging.info('shutting down instance %s on host %s',
                     instance, host_con.host)
        shutdown(host_con, instance)

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
    undefine(host_con, instance)

    logging.info('scheduling %s disk deletion on host %s',
                 instance, host_con.host)
    # TODO: lvm removal
    disk = '/srv/vmstore/%s/' % instance
    if host.path_exists(host_con, disk):
        host.schedule_delete(host_con, disk, '7 days')


def parse_memory(xml_root):
    '''find memory specs in parsed XML'''
    for tag in xml_root.findall('memory'):
        unit = tag.get('unit')
        assert unit == 'KiB'
        yield int(tag.text) * 1024


def parse_cpu(xml_root):
    '''find CPU specs in parsed XML'''
    for tag in xml_root.findall('vcpu'):
        yield int(tag.text)


# a device name (e.g. "sda"), path
# (e.g. /srv/vmstore/test.torproject.org/test.torproject.org-root) and
# type (e.g. "qcow2") as found in the libvirt XML file
disk_tuple = namedtuple('disk_tuple', ('dev', 'path', 'type'))


def parse_disks(xml_root):
    '''list disk paths in order, as a disk_tuple'''
    for devices in xml_root.findall('devices'):
        for disk in devices.findall('disk'):
            assert disk.get('type') == 'file' and disk.get('device') == 'disk'
            type = disk.find('driver').get('type')
            assert type in ('raw', 'qcow2')
            path = disk.find('source').get('file')
            dev = disk.find('target').get('dev')
            yield disk_tuple(dev, path, type)


def fetch_xml(con, instance):
    '''download the XML configuration for an instance'''
    buffer = io.BytesIO()
    instance_config = '/etc/libvirt/qemu/%s.xml' % instance
    try:
        con.get(instance_config, local=buffer)
    except OSError as e:
        logging.error('cannot fetch instance config from %s: %s',
                      instance_config, e)
        return False
    return buffer.getvalue()


def disk_json(con, disk_path, hide=True, dry=False):
    '''find disk information from qemu, as a json string'''
    command = 'qemu-img info --output=json %s' % disk_path
    try:
        result = con.run(command, hide=hide, dry=dry)
    except OSError as e:
        logging.error('failed to run %s: %s', command, e)
        return False
    return result.stdout


def swap_uuid(con, disk_path, hide=True, dry=False):
    '''find the UUID of the given SWAP file or disk'''
    result = con.run('blkid -t TYPE=swap -s UUID -o value %s' % disk_path,
                     hide=hide, dry=dry)
    return result.stdout.strip()


@task
def inventory(con, instance):
    '''fetch instance characteristics'''
    inventory = {}
    logging.info('fetching instance %s inventory from %s...',
                 instance, con.host)
    xml_root = ET.fromstring(fetch_xml(con, instance))
    # XXX: we drop duplicates in cpu and memory here
    inventory['cpu'], = list(parse_cpu(xml_root))
    logging.info('CPU: %s', inventory['cpu'])
    inventory['memory'], = list(parse_memory(xml_root))
    logging.info('memory: %s bytes (%s/%s)', inventory['memory'],
                 naturalsize(inventory['memory'], binary=True),
                 naturalsize(inventory['memory']))

    disks = OrderedDict()
    for dev, path, type in parse_disks(xml_root):
        j = disk_json(con, path)
        disk_info = json.loads(j)
        disk_info['xml_dev'] = dev
        disk_info['xml_type'] = type

        if path.endswith('-swap'):
            disk_info['swap_uuid'] = swap_uuid(con, path)
            logging.info('found swap %s: %s bytes (%s/%s) UUID:%s',
                         os.path.basename(path),
                         disk_info['virtual-size'],
                         naturalsize(disk_info['virtual-size'], binary=True),
                         naturalsize(disk_info['virtual-size']),
                         disk_info['swap_uuid'])
        else:
            logging.info('disk %s: %s bytes (%s/%s)',
                         os.path.basename(path),
                         disk_info['virtual-size'],
                         naturalsize(disk_info['virtual-size'], binary=True),
                         naturalsize(disk_info['virtual-size']))
        disks[path] = disk_info

    inventory['disks'] = disks
    logging.debug('generated inventory: %s', inventory)
    return inventory
