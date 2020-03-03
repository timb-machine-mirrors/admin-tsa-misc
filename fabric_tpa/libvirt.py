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
    con.run("virsh shutdown '%s'" % instance)


@task
def undefine(con, instance):
    '''remove instance configuration file'''
    con.run("virsh undefine '%s'" % instance)


@task
def instance_running(con, instance, hide=True, dry=False):
    '''check if an instance is running'''
    result = con.run('virsh list --state-running --name', hide=hide, dry=dry)
    return instance in result.stdout


@task
def retire_instance(host_con, instance):
    '''retire a libvirt instance

    This shuts down the instance, removes the configuration and its
    disk.
    '''
    # STEP 3
    if instance_running(host_con, instance):
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


def instance_parse_memory(xml_root):
    '''find memory specs in parsed XML'''
    for tag in xml_root.findall('memory'):
        unit = tag.get('unit')
        assert unit == 'KiB'
        yield int(tag.text) * 1024


def instance_parse_cpu(xml_root):
    '''find CPU specs in parsed XML'''
    for tag in xml_root.findall('vcpu'):
        yield int(tag.text)


# a device name (e.g. "sda"), path
# (e.g. /srv/vmstore/test.torproject.org/test.torproject.org-root) and
# type (e.g. "qcow2") as found in the libvirt XML file
disk_tuple = namedtuple('disk_tuple', ('dev', 'path', 'type'))


def instance_parse_disks(xml_root):
    '''list disk paths in order, as a disk_tuple'''
    for devices in xml_root.findall('devices'):
        for disk in devices.findall('disk'):
            assert disk.get('type') == 'file' and disk.get('device') == 'disk'
            type = disk.find('driver').get('type')
            assert type in ('raw', 'qcow2')
            path = disk.find('source').get('file')
            dev = disk.find('target').get('dev')
            yield disk_tuple(dev, path, type)


def instance_fetch_libvirt_xml(con, instance):
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


def instance_list_disks(con, instance):
    '''find the instance disks'''
    sftp = con.sftp()
    for disk in sftp.listdir_iter('/srv/vmstore/%s' % instance):
        logging.debug('found disk %s', disk.filename)
        yield '/srv/vmstore/%s/%s' % (instance, disk.filename)


def instance_disk_json(con, disk_path, hide=True):
    '''find disk information from qemu, as a json string'''
    command = 'qemu-img info --output=json %s' % disk_path
    try:
        result = con.run(command, hide=hide)
    except OSError as e:
        logging.error('failed to run %s: %s', command, e)
        return False
    return result.stdout


def instance_swap_uuid(con, disk_path, hide=True):
    '''find the UUID of the given SWAP file or disk'''
    result = con.run('blkid -t TYPE=swap -s UUID -o value %s' % disk_path,
                     hide=hide)
    return result.stdout.strip()


@task
def instance_inventory(con, instance):
    '''fetch instance characteristics'''
    inventory = {}
    logging.info('fetching instance %s inventory from %s...',
                 instance, con.host)
    xml_root = ET.fromstring(instance_fetch_libvirt_xml(con,
                                                        instance))
    # XXX: we drop duplicates in cpu and memory here
    inventory['cpu'], = list(instance_parse_cpu(xml_root))
    logging.info('CPU: %s', inventory['cpu'])
    inventory['memory'], = list(instance_parse_memory(xml_root))
    logging.info('memory: %s bytes (%s/%s)', inventory['memory'],
                 naturalsize(inventory['memory'], binary=True),
                 naturalsize(inventory['memory']))

    disks = OrderedDict()
    for dev, path, type in instance_parse_disks(xml_root):
        j = instance_disk_json(con, path)
        disk_info = json.loads(j)
        disk_info['xml_dev'] = dev
        disk_info['xml_type'] = type

        if path.endswith('-swap'):
            swap_uuid = instance_swap_uuid(con, path)
            disk_info['swap_uuid'] = swap_uuid
            logging.info('found swap %s: %s bytes (%s/%s) UUID:%s',
                         os.path.basename(path),
                         disk_info['virtual-size'],
                         naturalsize(disk_info['virtual-size'], binary=True),
                         naturalsize(disk_info['virtual-size']),
                         swap_uuid)
        else:
            logging.info('disk %s: %s bytes (%s/%s)',
                         os.path.basename(path),
                         disk_info['virtual-size'],
                         naturalsize(disk_info['virtual-size'], binary=True),
                         naturalsize(disk_info['virtual-size']))
        disks[path] = disk_info

    inventory['disks'] = disks
    return inventory
