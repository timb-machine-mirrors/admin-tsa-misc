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
import os.path
import sys

try:
    from fabric import task, Connection
except ImportError:
    sys.stderr.write('cannot find fabric, install with `apt install python3-fabric`')  # noqa: E501
    raise
# no check required, fabric depends on invoke
import invoke
try:
    from humanize import naturalsize
except ImportError:
    sys.stderr.write('cannot import humanize, sizes will be ugly')

    def naturalsize(size, *args, **kwargs):
        return size + 'B'


from . import libvirt
from . import host


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


@task(help={
    'ganeti-node': 'ganeti node to import instance into',
    'libvirt-host': 'libvirt host to import instance from',
})
def libvirt_import(instance_con, ganeti_node, libvirt_host):
    '''import instance into ganeti

    This will import the given hosts (INSTANCE_CON) from the KVM_HOST (string)
    into the GANETI_NODE.
    '''
    # check for required options, workaround for:
    # https://github.com/pyinvoke/invoke/issues/new
    if not libvirt_host:
        logging.error('libvirt host not provided')
        return False
    if not ganeti_node:
        logging.error('ganeti node not provided')
        return False
    libvirt_con = Connection(libvirt_host)
    ganeti_node_con = Connection(ganeti_node)

    # STEP 1, 2: inventory
    inventory = libvirt.instance_inventory(libvirt_con, instance_con.host)
    logging.debug('got inventory: %s', inventory)

    # STEP 3: authorized_keys hack
    pubkey = host.fetch_ssh_host_pubkey(ganeti_node_con)
    logging.info('fetched %s host key: %s', ganeti_node, pubkey)

    content = b"# %b pubkey for %b transfer\n%b\n" % (ganeti_node.encode('ascii'), instance_con.host.encode('ascii'), pubkey)  # noqa: E501
    host.append_to_file(libvirt_con, '/etc/ssh/userkeys/root', content)
    logging.info('allowed host %s to connect to %s as root',
                 ganeti_node, libvirt_host)

    # STEP 4: copy disks
    # TODO: check for free space
    logging.info('copying disks from %s to %s...', libvirt_host, ganeti_node)
    for path, disk in inventory['disks'].items():
        disk['basename'] = os.path.basename(disk['filename'])
        disk['filename_local'] = '/srv/' + disk['basename']
        if disk['filename'].endswith('-swap'):
            logging.info('skipping swap file %s', disk['filename'])
            continue
        command = "rsync -e 'ssh -i /etc/ssh/ssh_host_ed25519_key' -P root@%s:%s %s" % (libvirt_host, path, disk['filename_local'])  # noqa: E501
        logging.debug('command: %s', command)
        ganeti_node_con.run(command, pty=True)

    # STEP 5: create volumes
    logging.info('creating logical volumes...')
    for path, disk in inventory['disks'].items():
        logging.info('creating %s logical volume vg_ganeti/%s on host %s',
                     naturalsize(disk['virtual-size']),
                     disk['basename'],
                     ganeti_node)
        command = 'lvcreate -L {virtual-size}B -n {basename} vg_ganeti'.format(**disk)  # noqa: E501
        try:
            ganeti_node_con.run(command)
        except invoke.exceptions.UnexpectedExit as e:
            if 'already exists' in str(e.result.stderr):
                logging.warning('reusing existing logical volume')
                continue
            else:
                raise e
        disk['device_path'] = '/dev/vg_ganeti/' + disk['basename']

        if disk['basename'].endswith('-swap'):
            logging.info('creating swap UUID %s in %s',
                         disk['swap_uuid'], disk['device_path'])
            command = 'mkswap --uuid {swap_uuid} {device_path}'.format(**disk)  # noqa: E501
            ganeti_node_con.run(command)
        else:
            logging.info('converting qcow image %s into raw device %s',
                         disk['filename_local'], disk['device_path'])
            command = 'qemu-img convert {filename_local}  -O raw {device_path}'.format(**disk)  # noqa: E501
            ganeti_node_con.run(command)

    # STEP 6: launch instance
    disk_spec = ''
    i = 0
    for path, disk in inventory['disks'].items():
        disk_spec += ' --disk %d:adopt=%s' % (i, disk['filename_local'])
        # TODO: guess what goes on the HDDs!
        i += 1

    logging.info('launching adopted instance...')
    command = f'''gnt-instance add -t plain
    --net 0:ip=pool,network=gnt-fsn
    --no-name-check
    --no-ip-check
    -o debootstrap+default
    -n {ganeti_node}
    {disk_spec}
    --backend-parameters memory={inventory['memory']},vcpus={inventory['cpu']}
    {instance_con.host}'''
    logging.debug('command: %s', command)
    ganeti_master_con = Connection(getmaster(ganeti_node_con))
    ganeti_master_con.run(command)
