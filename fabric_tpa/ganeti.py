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
import re
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

from ruamel.yaml import YAML

from . import libvirt
from . import host


@task
def getmaster(con, hide=True):
    '''find master ganeti

    This can be used to detect if a node is running ganeti or not.'''
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


# troubleshooting:
# Fri Feb 21 16:42:18 2020  - WARNING: Can't find disk on node fsn-node-03.torproject.org  # noqa: E501
# gnt-instance activate-disks onionoo-backend-02.torproject.org
@task
def empty_node(node_con, master_host=None):
    '''migrate primary instances

    This migrates (using gnt-node migrate) *primary* instances away
    from this node, towards their secondary node. This is generally
    done in preperation for a reboot.

    This is *not* sufficient to retire a node, for that a full
    "evacuation" (including secondary nodes) needs to be performed.
    '''
    if master_host is None:
        master_host = getmaster(node_con)
    master_con = host.find_context(master_host, config=node_con.config)

    command = 'gnt-node migrate -f %s' % node_con.host
    logging.info('sending command %s to node %s', command, master_con.host)
    result = master_con.run(command, warn=True)
    # TODO: failover master?
    return (result.ok
            and (
                "All instances migrated successfully." in result.stdout
                or ("No primary instances on node %s, exiting." % master_con.host) in result.stdout  # noqa: E501
            )
    )


@task
def stop(ganeti_con, instance):
    '''stop an instance

    This just stops an instance, on what is assumed to be the ganeti master.
    '''
    logging.info('stopping instance %s on %s', instance, ganeti_con.host)
    return ganeti_con.run('gnt-instance stop %s' % instance)


@task
def start(ganeti_con, instance):
    '''stop an instance

    This just stops an instance, on what is assumed to be the ganeti master.
    '''
    logging.info('starting instance %s on %s', instance, ganeti_con.host)
    return ganeti_con.run('gnt-instance start %s' % instance)


@task
def renumber_instance(ganeti_con, instance):
    '''change the IP address of an instance

    This does the following:

    1. connects to ganeti node
    2. finds its master
    3. fetches network information from the master
       (fetch-instance-info and find-instance-ipconfig)
    4. stops the instance
    5. mounts its disk
    6. rewrites the interfaces file (with host.rewrite-interfaces)
    7. unmounts the disk
    8. starts the instance
    '''
    ganeti_master_con = Connection(getmaster(ganeti_con))
    instance_info = fetch_instance_info(ganeti_master_con, instance)
    data, = YAML().load(instance_info)
    disks = data['Disks']
    disk0 = disks[0]
    assert 'disk/0' in disk0
    disk_path = disk0['on primary'].split(' ')[0]
    ipconfig = find_instance_ipconfig(ganeti_master_con, instance,
                                      instance_info)
    # this succeeds even if already stopped
    stop(ganeti_master_con, instance)
    need_kpartx_deactivate = False
    with host.mount_then_umount(ganeti_con, disk_path,
                                '/mnt', warn=True) as res:
        if res.failed:
            logging.warning('cannot mount partition directly: %s', res.stderr)
            logging.info('trying kpartx activation')
            res = ganeti_con.run('kpartx -av %s' % disk_path)
            need_kpartx_deactivate = True
            # add map vg_ganeti-b80808ec--174c--4715--b9cf--f83c07d346cf.disk0p1 (253:62): 0 41940992 linear 253:58 2048
            _, _, part, _ = res.stdout.split(' ', 3)
            host.mount(ganeti_con, '/dev/mapper/%s' % part, '/mnt')
        host.rewrite_interfaces(ganeti_con, ipconfig,
                                path='/mnt/etc/network/interfaces')
    if need_kpartx_deactivate:
        logging.info('disabling kpartx mappings')
        ganeti_con.run('kpartx -dv %s' % disk_path)

    start(ganeti_master_con, instance)
    cmd = 'printf "%s %s\\n%s %s\\n" >> /etc/hosts' % (ipconfig.ipv4,
                                                       instance,
                                                       ipconfig.ipv6,
                                                       instance)
    logging.info('use this to add the new IP to local DNS: %s', cmd)


@task
def fetch_instance_info(ganeti_con, instance, hide=True):
    '''fetch the instance information

    This just runs gnt-instance info on the ganeti server and returns
    the output. It's mostly an internal function.
    '''
    info = ganeti_con.run('gnt-instance info %s' % instance, hide=hide).stdout
    logging.debug('loaded instance %s info from %s: %s',
                  instance, ganeti_con.host, info)
    return info


@task
def fetch_network_info(ganeti_con, network='gnt-fsn', hide=True):
    '''fetch the network information

    This just runs gnt-network info on the given network and returns
    the output. It's mostly an internal function.
    '''
    info = ganeti_con.run('gnt-network info %s' % network, hide=hide).stdout
    logging.debug('loaded network %s information from %s: %s',
                  network, ganeti_con.host, info)
    return info


# this regex should match the output of gnt-network info
GANETI_NETWORK_REGEX = r'^\s+(Subnet|Gateway|IPv6 Subnet|IPv6 Gateway):\s+(.*)$'  # noqa: E501


@task
def find_instance_ipconfig(ganeti_con, instance, instance_info=None):
    '''compute the network information for the given instance

    This connects to the ganeti node (assumed to be a ganeti master)
    and fetches IP address information from the node. From there, it
    also fetches information from the ganeti network to get parameters
    like the network and gateway.

    It returns a host.ipconfig tuple and is therefore mostly for
    internal use.
    '''
    # allow using a cache for this expensive check
    if instance_info is None:
        instance_info = fetch_instance_info(ganeti_con, instance)
    data, = YAML().load(instance_info)
    nics = data['NICs']
    # TODO: support multiple NICs
    ipv4 = nics[0]['IP']
    mac = nics[0]['MAC']
    network = nics[0]['network']
    facts = {}
    # XXX: looks like the output of `gnt-network info` is *not* YAML,
    # at least ruamel.yaml freaks out with:
    #
    # ScannerError: mapping values are not allowed here
    #   in "<unicode string>", line 4, column 9:
    #       Subnet: 116.202.120.160/27
    #             ^ (line: 4)
    #
    # so revert back to using a regex
    network_info = fetch_network_info(ganeti_con, network)
    for match in re.finditer(GANETI_NETWORK_REGEX,
                             network_info,
                             re.MULTILINE):
        facts[match.group(1)] = match.group(2)
    logging.debug('found networking facts: %s', facts)
    ipv4_subnet = facts['Subnet'].split('/')[-1]
    ipv6_net, ipv6_subnet = facts['IPv6 Subnet'].split('/')
    # HACK: we use a local invoke context instead of the remote
    ipv6 = host.ipv6_slaac(invoke.Context(),
                           ipv6_net,
                           mac)
    conf = host.ipconfig(ipv4,
                         ipv4_subnet,
                         facts['Gateway'],
                         ipv6,
                         ipv6_subnet,
                         facts['IPv6 Gateway'])
    logging.debug('ipconfig: %s', conf)
    return conf


def copy_disks(libvirt_con, ganeti_con, target_dir, disks):
    '''helper function to copy disks between instances

    Relies heavily on a modified inventory as provided by
    libvirt.inventory but modified by libvirt_import.
    '''
    for path, disk in disks.items():
        if disk['filename'].endswith('-swap'):
            logging.info('skipping swap file %s', disk['filename'])
            continue
        command = "rsync -e 'ssh -i /etc/ssh/ssh_host_ed25519_key' -P root@%s:%s %s" % (libvirt_con.host, path, target_dir)  # noqa: E501
        logging.debug('command: %s', command)
        ganeti_con.run(command, pty=True)


@task(help={
    'libvirt-host': 'libvirt host to import instance from',
    'ganeti-node': 'ganeti node to import instance into',
    'copy': 'copy the disks between the nodes (default: True)',
    'adopt': 'adopt the instance in ganeti (default: False)',
    'suspend': 'suspend the node while copying disks (default: False)',
})
def libvirt_import(instance_con, libvirt_host, ganeti_node,
                   copy=True, adopt=False, suspend=False):
    '''import instance into ganeti

    This will import the given hosts (INSTANCE_CON) from the KVM_HOST
    (string) into the GANETI_NODE. You can set *copy* to False to
    avoid running rsync if a copy of the disks already exists. rsync
    is fast, but it can still be pretty slow to run this command
    repeatedly because rsync still needs to check the entire disk.

    By default, the resulting disk is not "adopted", or "added" if you
    will, into Ganeti, set *adopt* to False to skip that step.

    Use SUSPEND to suspend the instance before the copy, which is
    preferable to get a consistent disk image, but might be disruptive
    for production host (False by default).

    '''
    # check for required options, workaround for:
    # https://github.com/pyinvoke/invoke/issues/new
    if not libvirt_host:
        logging.error('libvirt host not provided')
        return False
    if not ganeti_node:
        logging.error('ganeti node not provided')
        return False
    libvirt_con = Connection(libvirt_host, config=instance_con.config)
    ganeti_node_con = Connection(ganeti_node, config=instance_con.config)

    # STEP 1, 2: inventory
    inventory = libvirt.inventory(libvirt_con, instance_con.host)

    # STEP 3: authorized_keys hack
    pubkey = host.fetch_ssh_host_pubkey(ganeti_node_con)
    logging.info('fetched %s host key: %s', ganeti_node, pubkey)

    content = b"# %b pubkey for %b transfer\n%b\n" % (ganeti_node.encode('ascii'), instance_con.host.encode('ascii'), pubkey)  # noqa: E501
    host.append_to_file(libvirt_con, '/etc/ssh/userkeys/root', content)
    logging.info('allowed host %s to connect to %s as root',
                 ganeti_node, libvirt_host)

    # STEP 4: copy disks
    spool_dir = '/srv/'
    # rest of the code assumes this has a trailing slash
    assert spool_dir.endswith('/')
    if copy:
        # TODO: check for free space
        logging.info('copying disks from %s to %s...',
                     libvirt_host, ganeti_node)
        if suspend:
            # TODO: warn users about downtime
            try:
                with libvirt.suspend_then_resume(libvirt_con, instance_con.host):  # noqa: E501
                    copy_disks(libvirt_con,
                               ganeti_node_con,
                               spool_dir,
                               inventory['disks'])
            except invoke.exceptions.UnexpectedExit as e:
                logging.error('failed to suspend or resume host: %s', e.result)
                return False
        else:
                    copy_disks(libvirt_con,
                               ganeti_node_con,
                               spool_dir,
                               inventory['disks'])
    else:
        logging.info('skipping disk copy as requested')

    # STEP 5: create volumes
    logging.info('creating logical volumes...')
    for path, disk in inventory['disks'].items():
        disk['basename'] = os.path.basename(disk['filename'])
        disk['filename_local'] = spool_dir + disk['basename']
        disk['device_path'] = '/dev/vg_ganeti/' + disk['basename']
        logging.info('creating %s logical volume vg_ganeti/%s on host %s',
                     naturalsize(disk['virtual-size'], binary=True),
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

    logging.info('initializing disks...')
    for path, disk in inventory['disks'].items():
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
    # TODO: order matters here! in cupani, -lvm ended up before -root
    # and that broke the bootloader
    for path, disk in inventory['disks'].items():
        disk_spec += ' --disk %d:adopt=%s' % (i, disk['basename'])
        # TODO: guess what goes on the HDDs!
        i += 1

    inventory['memory_human'] = naturalsize(inventory['memory'], gnu=True)
    command = f'''gnt-instance add -t plain \
    --net 0:ip=pool,network=gnt-fsn \
    --no-name-check \
    --no-ip-check \
    -o debootstrap+default \
    -n {ganeti_node} \
    {disk_spec} \
    --backend-parameters \
    memory={inventory['memory_human']},vcpus={inventory['cpu']} \
    {instance_con.host}'''
    logging.debug('command: %s', command)
    if adopt:
        logging.info('launching adopted instance...')
        ganeti_master_con = Connection(getmaster(ganeti_node_con))
        ganeti_master_con.run(command)
    else:
        logging.info('skipping ganeti adoption: %s', command)

    # TODO: remove old disks

    # TODO: remaining procedure:
    # STEP 9. IP address change on new instance:
    #
    #      edit `/etc/hosts` and `/etc/network/interfaces` by hand and add
    #      IPv4 and IPv6 ip. IPv4 configuration can be found in:
    #
    #          gnt-instance show $INSTANCE
    #
    #      Latter can be guessed by concatenating `2a01:4f8:fff0:4f::` and
    #      the IPv6 local local address without `fe80::`. For example: a
    #      link local address of `fe80::266:37ff:fe65:870f/64` should yield
    #      the following configuration:
    #
    #          iface eth0 inet6 static
    #              accept_ra 0
    #              address 2a01:4f8:fff0:4f:266:37ff:fe65:870f/64
    #              gateway 2a01:4f8:fff0:4f::1
    #
    #      TODO: reuse `gnt-debian-interfaces` from the ganeti puppet
    #      module script here?
    #
    # STEP 10. functional tests: change your `/etc/hosts` to point to the new
    #     server and see if everything still kind of works
    #
    # STEP 11. shutdown original instance
    #
    # STEP 12. resync and reconvert image, on the Ganeti MASTER NODE:
    #
    #         gnt-instance stop $INSTANCE
    #
    # [...]
    #
    # STEP 13. switch to DRBD, still on the Ganeti MASTER NODE:
    #
    #         gnt-instance modify -t drbd $INSTANCE
    #         gnt-instance failover $INSTANCE
    #         gnt-instance startup $INSTANCE
    #
    # STEP 14. redo IP adress change in `/etc/network/interfaces` and
    # `/etc/hosts`
    #
    # STEP 15. final functional test
    #
    # STEP 16. global IP address change
    #
    # STEP 17. decomission old instance ([[retire-a-host]])
