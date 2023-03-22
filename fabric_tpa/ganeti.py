#!/usr/bin/python3
# coding: utf-8

"""reboot hosts"""
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

from datetime import datetime, timedelta, timezone
import logging
import os.path
import re
import sys
import time

try:
    from fabric import task
except ImportError:
    sys.stderr.write(
        "cannot find fabric, install with `apt install python3-fabric`"
    )
    raise
# no check required, fabric depends on invoke
import invoke
from invoke.exceptions import Failure, Exit
import paramiko.ssh_exception

try:
    from humanize import naturalsize
except ImportError:
    sys.stderr.write("cannot import humanize, sizes will be ugly")

    def naturalsize(size, *args, **kwargs):
        return size + "B"


from ruamel.yaml import YAML

from . import libvirt
from . import host


@task(autoprint=True)
def getmaster(con, hide=True, dry=False):
    """find master ganeti

    This can be used to detect if a host is running ganeti or not."""
    master = False
    logging.info("checking for ganeti master on host %s", con.host)
    result = con.run("gnt-cluster getmaster", hide=hide, dry=dry, warn=True)
    if result.ok:
        master = result.stdout.strip()
        logging.info("ganeti node detected with master %s", master)
        return master
    raise Failure(result, "%s is not a ganeti node" % con.host)


# troubleshooting:
# Fri Feb 21 16:42:18 2020  - WARNING: Can't find disk on node fsn-node-03.torproject.org
# gnt-instance activate-disks onionoo-backend-02.torproject.org
@task
def empty_node(node_con, master_host=None):
    """migrate primary instances

    This migrates (using gnt-node migrate) *primary* instances away
    from this node, towards their secondary node. This is generally
    done in preperation for a reboot.

    This is *not* sufficient to retire a node, for that a full
    "evacuation" (including secondary nodes) needs to be performed.
    """
    if master_host is None:
        master_host = getmaster(node_con)
    master_con = host.find_context(master_host, config=node_con.config)

    command = "gnt-node migrate -f %s" % node_con.host
    logging.info("sending command %s to node %s", command, master_con.host)
    result = master_con.run(command, warn=True)

    # TODO: migrate on the next node might fail with:
    # WARNING: Can't find disk on node fsn-node-03.torproject.org
    # solution is to activate-disk on that instance

    # TODO: failover master?
    return (result.ok and "All instances migrated successfully." in result.stdout) or (
        "No primary instances on node %s, exiting." % node_con.host
    ) in result.stdout


@task
def stop_instances(
        node_con,
        master_host="fsn-node-01.torproject.org",
        delay_shutdown=None,
        delay_down=None,
):
    """stop all instances on the given Ganeti node"""

    # this is a local import to fix an import loop with reboot.py
    from .reboot import (
        ShutdownType,
        shutdown,
        wait_for_shutdown,
        DEFAULT_DELAY_SHUTDOWN,
        DEFAULT_DELAY_DOWN,
    )
    if delay_shutdown is None:
        delay_shutdown = DEFAULT_DELAY_SHUTDOWN
    if delay_down is None:
        delay_down = DEFAULT_DELAY_DOWN

    master_con = host.find_context(master_host, config=node_con.config)
    logging.info(
        "finding instances running on %s from %s ", node_con.host, master_con.host
    )
    instances = list(
        _list_instances(
            master_con,
            {
                "pnode": node_con.host,
                "admin_state": "up",
            },
        )
    )
    if not len(instances):
        return []

    # issue shutdown procedures for all instances on the node
    #
    # FIXME: this is cargo-culted from shutdown_and_wait, but we can't
    # use that because we need to parallelize the shutdowns
    #
    # arguably, shutdown_and_wait could be improved to yield control
    # back while it waits, with async or something, but it's simpler
    # to copy-paste for now.
    #
    # Could this be done with a ThreadingGroup?
    for instance in instances:
        con = host.find_context(instance)
        try:
            shutdown(con, ShutdownType.halt, "rebooting parent ganeti node", delay_shutdown)
        except invoke.UnexpectedExit as e:
            raise Exit("unexpected error issuing reboot on %s: %s" % (con.host, e))
        except (EOFError, OSError, paramiko.ssh_exception.SSHException) as e:
            logging.warning("failed to connect to %s, assuming down: %s", con.host, e)

    logging.info("scheduled reboots with %s minute delay on %s", delay_shutdown, " ".join(instances))

    if delay_shutdown > 0:
        now = datetime.now(timezone.utc)
        then = now + timedelta(minutes=delay_shutdown)
        logging.info(
            "waiting %d minutes for reboot to happen, at %s (now is %s)",
            delay_shutdown,
            then,
            now,
        )
        # NOTE: we convert minutes to seconds here
        time.sleep(delay_shutdown * 60)

    for instance in instances:
        con = host.find_context(instance)
        logging.info("waiting for %s to shutdown", con.host)
        if not wait_for_shutdown(con, delay_down):
            logging.warning(
                "host %s was still up after %d seconds, ignoring",
                con.host,
                delay_down,
            )
    # end of FIXME

    logging.info(
        "forcibly stopping all instances (%d) on %s from master %s",
        len(instances),
        node_con.host,
        master_con.host,
    )

    # ganeti parallelizes this for us, which is good luck because I
    # couldn't figure out how to run a specific task inside a
    # ThreadGroup
    master_con.run("gnt-instance shutdown --force-multiple %s" % " ".join(instances))

    return instances


@task
def stop(instance_con, master_host="fsn-node-01.torproject.org"):
    """stop an instance

    This just stops an instance, on what is assumed to be the ganeti
    master. Note that `gnt-instance stop` succeeds even if the
    instance is already stopped.
    """
    master_con = host.find_context(master_host, config=instance_con.config)
    logging.info("stopping instance %s on %s", instance_con.host, master_con.host)
    return master_con.run("gnt-instance stop %s" % instance_con.host)


@task
def start(instance_con, master_host="fsn-node-01.torproject.org"):
    """stop an instance

    This just stops an instance, on what is assumed to be the ganeti master.

    Error handling should be done by the caller.
    """
    master_con = host.find_context(master_host, config=instance_con.config)
    logging.info("starting instance %s on %s", instance_con.host, master_con.host)
    return master_con.run("gnt-instance start %s" % instance_con.host)


@task
def is_running(instance_con, master_host="fsn-node-01.torproject.org"):
    master_con = host.find_context(master_host, config=instance_con.config)
    logging.info(
        "checking on %s if instance %s is running", master_con.host, instance_con.host
    )
    res = master_con.run(
        "gnt-instance list --no-headers -o admin_state %s" % instance_con.host,
        warn=True,
        hide=True,
    )
    if res.failed:
        logging.warning(
            "instance %s not found in Ganeti master %s",
            instance_con.host,
            master_con.host,
        )
        return False
    return res.stdout.strip() == "up"


@task
def retire(instance_con, master_host="fsn-node-01.torproject.org"):
    """remove the given instance in 7 days, stopping  immediately if running"""
    master_con = host.find_context(master_host, config=instance_con.config)
    if is_running(instance_con, master_con):
        # this might fail if the instance doesn't exist, that's fine,
        # we'll abort with the command's stderr
        stop(instance_con, master_con)
    else:
        logging.info("instance %s not running, no stop required", instance_con.host)
    logging.info(
        "scheduling %s instance removal on host %s", instance_con.host, master_con.host
    )
    return host.schedule_job(
        master_con,
        "gnt-instance remove --force %s" % instance_con.host,
        host.RETIREMENT_DELAY,
    )


@task
def renumber_instance(instance_con, ganeti_node, dostart=True):
    """change the IP address of an instance

    This does the following:

    1. connects to the primary ganeti node
    2. finds its master
    3. fetches network information from the master
       (fetch-instance-info and find-instance-ifconfig)
    4. stops the instance
    5. mounts its disk
    6. rewrites the interfaces file (with host.rewrite-interfaces)
    7. unmounts the disk
    8. starts the instance (if --dostart, default)
    """
    # STEP 9. IP address change on new instance
    # STEP 14. redo IP adress change in `/etc/network/interfaces` and
    # `/etc/hosts`
    ganeti_node_con = host.find_context(ganeti_node, config=instance_con.config)
    ganeti_master_con = host.find_context(
        getmaster(ganeti_node_con), config=instance_con.config
    )
    instance_info = fetch_instance_info(instance_con, ganeti_master_con)
    (data, ) = YAML().load(instance_info)
    disks = data["Disks"]
    disk0 = disks[0]
    assert "disk/0" in disk0
    if "child devices" in disk0:
        # we inspect the "child devices" field, because the main "on
        # primary" fields are only active when the VM is started or, more
        # specifically when disks are "activated", which is not the case
        # when the VM is stopped, which we're about to do here.
        for child in disk0["child devices"]:
            logging.debug("child: %s", dict(child))
            disk_path = child["on primary"].split(" ")[0]
            if disk_path.endswith('_data'):
                break
        else:
            logging.error("could not find child device")
            return False
    else:
        # "plain" template fallback
        disk_path = disk0["on primary"].split(" ")[0]
    ifconfig = find_instance_ifconfig(instance_con, ganeti_master_con, instance_info)
    # this succeeds even if already stopped
    stop(instance_con, ganeti_master_con)
    need_kpartx_deactivate = False
    logging.info("mounting %s over /mnt on host %s", disk_path, ganeti_master_con.host)
    with host.mount_then_umount(ganeti_node_con, disk_path, "/mnt", warn=True) as res:
        if res.failed:
            logging.warning("cannot mount partition directly: %s", res.stderr)
            logging.info("trying kpartx activation")
            # XXX: error handling?
            res = ganeti_node_con.run("kpartx -av %s" % disk_path)
            need_kpartx_deactivate = True
            # add map vg_ganeti-b80808ec--174c--4715--b9cf--f83c07d346cf.disk0p1 (253:62): 0 41940992 linear 253:58 2048
            _, _, part, _ = res.stdout.split(" ", 3)
            host.mount(ganeti_node_con, "/dev/mapper/%s" % part, "/mnt")
        res = host.rewrite_interfaces_ifconfig(
            ganeti_node_con, ifconfig, path="/mnt/etc/network/interfaces"
        )
        ipv4_address_old, ipv6_address_old = host.parse_rewrite_interfaces_diff(res.stdout)

        if ipv4_address_old is None:
            logging.warning("could not find old IP address, looking in interfaces.d")
            try:
                ganeti_node_con.sftp().file("/mnt/etc/network/interfaces.d/eth0")
            except IOError:
                logging.warning("/mnt/etc/network/interfaces.d/eth0 missing")
            else:
                res = host._diff_file(ganeti_node_con, "/mnt/etc/network/interfaces.d/eth0", "/mnt/etc/network/interfaces")
                ipv4_address_old, ipv6_address_old = host.parse_rewrite_interfaces_diff(res.stdout)
                try:
                    ganeti_node_con.sftp().remove("/mnt/etc/network/interfaces.d/eth0")
                except Exception as e:
                    logging.warning("failed to remove old /mnt/etc/network/interfaces.d/eth0 file: %s", e)

        host._rewrite_hosts(
            ganeti_node_con,
            instance_con.host,
            ifconfig.ipv4,
            ifconfig.ipv6,
            path="/mnt/etc/hosts",
        )
    if need_kpartx_deactivate:
        logging.info("disabling kpartx mappings")
        # XXX: error handling?
        ganeti_node_con.run("kpartx -dv %s" % disk_path)

    if dostart:
        # this might fail and abort the script here, that's fine.
        start(instance_con, ganeti_master_con)
    # TODO: all this could be done for real:
    # STEP 10. functional tests: change your `/etc/hosts` to point to the new
    #     server and see if everything still kind of works
    #
    cmd = 'printf "%s %s\\n%s %s\\n" | sudo tee -a /etc/hosts' % (
        ifconfig.ipv4,
        instance_con.host,
        ifconfig.ipv6,
        instance_con.host,
    )
    logging.warning("use this to add the new IP to local DNS: %s", cmd)
    logging.warning(
        "perform tests, then redo the sync procedure and this procedure, then..."
    )
    logging.warning("make sure you change the external DNS as well")
    # STEP 15. final functional test
    # STEP 16. global IP address change
    logging.warning("commands:")
    magic_grep = "grep -n -r -e %s -e %s" % (ipv4_address_old, ipv6_address_old)
    commands = [
        # LDAP vi
        'ssh -tt db.torproject.org ldapvi -ZZ --encoding=ASCII --ldap-conf -h db.torproject.org -D "uid=$USER,ou=users,dc=torproject,dc=org"',  # noqa: E501
        # puppet on the puppet master, to open up firewall
        "ssh root@puppet.torproject.org puppet agent -t",
        # puppet on the host
        "ssh %s puppet agent -t" % instance_con.host,
        # on the host, in /etc and /srv
        "ssh %s %s /etc /srv" % (instance_con.host, magic_grep),
        # in all the tor source
        "%s ~/src/tor" % magic_grep,
        # puppet everywhere
        'cumin-all "puppet agent -t"',
        # on all hosts, in /etc
        "cumin-all '%s /etc'" % magic_grep,
    ]
    for command in commands:
        logging.warning("# %s", command)
    logging.warning("also do upstream reverse DNS")


def fetch_instance_info(
    instance_con, master_host="fsn-node-01.torproject.org", hide=True, dry=False
):
    """fetch the instance information

    This just runs gnt-instance info on the ganeti server and returns
    the output. It's mostly an internal function.
    """
    master_con = host.find_context(master_host, config=instance_con.config)
    # XXX: error handling
    info = master_con.run(
        "gnt-instance info %s" % instance_con.host, hide=hide, dry=dry
    ).stdout
    logging.debug(
        "loaded instance %s info from %s: %s", instance_con.host, master_con.host, info
    )
    return info


def fetch_network_list(ganeti_con, hide=True, dry=False):
    info = ganeti_con.run(
        "gnt-network list -o name --no-headers", hide=hide, dry=dry, warn=True
    )
    if info.failed:
        logging.warning(
            "cannot load network list from %s: %s", ganeti_con.host, info.stderr
        )
        return []
    logging.debug("loaded network list from %s: %s", ganeti_con.host, info.stdout)
    # skip header
    for line in info.stdout.split("\n"):
        yield line.strip()


def fetch_network_info(ganeti_con, network="gnt-fsn", hide=True, dry=False):
    """fetch the network information

    This just runs gnt-network info on the given network and returns
    the output. It's mostly an internal function.
    """
    # XXX: error handling
    info = ganeti_con.run("gnt-network info %s" % network, hide=hide, dry=dry).stdout
    logging.debug(
        "loaded network %s information from %s: %s", network, ganeti_con.host, info
    )
    return info


@task
def list_instances(ganeti_con, primary=None, admin_state="up"):
    # need a wrapper around the generator, otherwise Autoprint only
    # prints ... the generator's repr
    filters = {"admin_state": admin_state}
    if primary:
        filters["pnode"] = primary
    for instance in _list_instances(ganeti_con, filters):
        print(instance)


def _list_instances(ganeti_con, filters={}):
    command = """gnt-instance list --no-header -o name"""
    if filters:
        items = []
        for key, val in filters.items():
            items.append('%s == "%s"' % (key, val))
        command += " --filter '%s'" % " and ".join(items)
    logging.debug("command: %s", command)
    info = ganeti_con.run(command, warn=True, hide=True)
    if info.failed:
        logging.warning(
            "cannot load list of instances from Ganeti node %s matching filter %s",
            ganeti_con.host,
            filters,
        )
        return []
    for line in info.stdout.split("\n"):
        if line.strip():
            yield line.strip()


# this regex should match the output of gnt-network info
GANETI_NETWORK_REGEX = (
    r"^\s+(Subnet|Gateway|IPv6 Subnet|IPv6 Gateway):\s+(.*)$"
)


@task
def find_instance_ifconfig(
    instance_con, master_host="fsn-node-01.torproject.org", instance_info=None
):
    """compute the network information for the given instance

    This connects to the ganeti node (assumed to be a ganeti master)
    and fetches IP address information from the node. From there, it
    also fetches information from the ganeti network to get parameters
    like the network and gateway.

    It returns a host.ifconfig tuple and is therefore mostly for
    internal use.

    instance-info is an internal parameter and should be ignored.
    """
    master_con = host.find_context(master_host, config=instance_con.config)
    # allow using a cache for this expensive check
    if instance_info is None:
        instance_info = fetch_instance_info(instance_con, master_con)
    (data,) = YAML().load(instance_info)
    nics = data["NICs"]
    # TODO: support multiple NICs
    ipv4 = nics[0]["IP"]
    mac = nics[0]["MAC"]
    network = nics[0]["network"]
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
    network_info = fetch_network_info(master_con, network)
    for match in re.finditer(GANETI_NETWORK_REGEX, network_info, re.MULTILINE):
        facts[match.group(1)] = match.group(2)
    logging.debug("found networking facts: %s", facts)
    ipv4_subnet = facts["Subnet"].split("/")[-1]
    ipv6 = facts.get("IPv6 Subnet")
    if ipv6 is None:
        logging.warning(
            "no IPv6 subnet found on instance %s, skipping IPv6", instance_con.host
        )
        ipv6_net, ipv6_subnet, ipv6_gateway = None, None, None
    else:
        ipv6_net, ipv6_subnet = ipv6.split("/")
        ipv6_gateway = facts["IPv6 Gateway"]
    # HACK: we use a local invoke context instead of the remote
    ipv6 = host.ipv6_slaac(invoke.Context(), ipv6_net, mac)
    conf = host.ifconfig(
        ipv4, ipv4_subnet, facts["Gateway"], ipv6, ipv6_subnet, ipv6_gateway
    )
    logging.debug("ifconfig: %s", conf)
    return conf


def copy_disks(libvirt_con, ganeti_con, target_dir, disks):
    """helper function to copy disks between instances

    Relies heavily on a modified inventory as provided by
    libvirt.inventory but modified by libvirt_import.
    """
    for path, disk in disks.items():
        if disk["filename"].endswith("-swap"):
            logging.info("skipping swap file %s", disk["filename"])
            continue
        command = "rsync --copy-devices --copy-links -e 'ssh -i /etc/ssh/ssh_host_ed25519_key' -P root@%s:%s %s" % (
            libvirt_con.host,
            path,
            target_dir,
        )
        logging.debug("command: %s", command)
        # XXX: error handling
        ganeti_con.run(command, pty=True)


@task(
    help={
        "libvirt-host": "libvirt host to import instance from",
        "ganeti-node": "ganeti node to import instance into",
        "copy": "copy the disks between the nodes (default: True)",
        "adopt": "adopt the instance in ganeti (default: False)",
        "suspend": "suspend the node while copying disks (default: False)",
        "network_name": "name of the network to allocate into (default: gnt-fsn13-02)",
    }
)
def libvirt_import(
    instance_con,
    libvirt_host,
    ganeti_node,
    copy=True,
    adopt=False,
    suspend=False,
    network_name="gnt-fsn13-02",
):
    """import instance into ganeti

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

    """
    # check for required options, workaround for:
    # https://github.com/pyinvoke/invoke/issues/new
    if not libvirt_host:
        logging.error("libvirt host not provided")
        return False
    if not ganeti_node:
        logging.error("ganeti node not provided")
        return False
    libvirt_con = host.find_context(libvirt_host, config=instance_con.config)
    ganeti_node_con = host.find_context(ganeti_node, config=instance_con.config)

    # STEP 1, 2: inventory
    inventory = libvirt.inventory(instance_con, libvirt_con)

    # STEP 3: authorized_keys hack
    pubkey = host.fetch_ssh_host_pubkey(ganeti_node_con).strip()
    logging.info("fetched %s host key: %s", ganeti_node, pubkey)

    comment = b"# %b pubkey for %b transfer" % (
        ganeti_node.encode("ascii"),
        instance_con.host.encode("ascii"),
    )
    host.ensure_ssh_key(
        libvirt_con, path="/etc/ssh/userkeys/root", key=pubkey, comment=comment
    )
    logging.info("allowed host %s to connect to %s as root", ganeti_node, libvirt_host)

    # STEP 4: copy disks
    spool_dir = "/srv/"
    # rest of the code assumes this has a trailing slash
    assert spool_dir.endswith("/")
    if copy:
        # TODO: check for free space
        logging.info("copying disks from %s to %s...", libvirt_host, ganeti_node)
        if suspend:
            # TODO: warn users about downtime
            try:
                with libvirt.suspend_then_resume(
                    instance_con, libvirt_con
                ):
                    copy_disks(
                        libvirt_con, ganeti_node_con, spool_dir, inventory["disks"]
                    )
            except invoke.exceptions.UnexpectedExit as e:
                logging.error("failed to suspend or resume host: %s", e.result)
                return False
        else:
            copy_disks(libvirt_con, ganeti_node_con, spool_dir, inventory["disks"])
    else:
        logging.info("skipping disk copy as requested")

    # STEP 5: create volumes
    logging.info("creating logical volumes...")
    for path, disk in inventory["disks"].items():
        disk["basename"] = os.path.basename(disk["filename"])
        disk["filename_local"] = spool_dir + disk["basename"]
        disk["device_path"] = "/dev/vg_ganeti/" + disk["basename"]
        logging.info(
            "creating %s logical volume vg_ganeti/%s on host %s",
            naturalsize(disk["virtual-size"], binary=True),
            disk["basename"],
            ganeti_node,
        )
        command = "lvcreate -L {virtual-size}B -n {basename} vg_ganeti".format(
            **disk
        )
        try:
            ganeti_node_con.run(command)
            # XXX: error handling?
        except invoke.exceptions.UnexpectedExit as e:
            if "already exists" in str(e.result.stderr):
                logging.warning("reusing existing logical volume")
                continue
            else:
                raise e

    logging.info("initializing disks...")
    for path, disk in inventory["disks"].items():
        if disk["basename"].endswith("-swap"):
            logging.info(
                "creating swap UUID %s in %s", disk["swap_uuid"], disk["device_path"]
            )
            command = "mkswap --uuid {swap_uuid} {device_path}".format(
                **disk
            )
            ganeti_node_con.run(command)
            # XXX: error handling
        else:
            logging.info(
                "converting qcow image %s into raw device %s",
                disk["filename_local"],
                disk["device_path"],
            )
            command = "qemu-img convert {filename_local}  -O raw {device_path}".format(
                **disk
            )
            ganeti_node_con.run(command)
            # XXX: error handling

    # STEP 6: launch instance
    disk_spec = ""
    i = 0
    # TODO: order matters here! in cupani, -lvm ended up before -root
    # and that broke the bootloader
    for path, disk in inventory["disks"].items():
        disk_spec += " --disk %d:adopt=%s" % (i, disk["basename"])
        # TODO: guess what goes on the HDDs!
        i += 1

    inventory["memory_human"] = naturalsize(inventory["memory"], gnu=True)
    instance_name = instance_con.host
    if not instance_name.endswith(".torproject.org"):
        # normalize VM name:
        instance_name += ".torproject.org"
    command = f"""gnt-instance add -t plain \
    --net 0:ip=pool,network={network_name} \
    --no-name-check \
    --no-ip-check \
    -o debootstrap+default \
    -n {ganeti_node} \
    {disk_spec} \
    --backend-parameters \
    memory={inventory['memory_human']},vcpus={inventory['cpu']} \
    {instance_name}"""
    logging.debug("command: %s", command)
    if adopt:
        logging.info("launching adopted instance...")
        ganeti_master_con = host.find_context(
            getmaster(ganeti_node_con), config=instance_con.config
        )
        ganeti_master_con.run(command)
        # XXX: error handling
    else:
        logging.info("skipping ganeti adoption: %s", command)

    # TODO: remove old disks
    # STEP 11. shutdown original instance
    #
    # STEP 12. resync and reconvert image, on the Ganeti MASTER NODE:
    #
    #         gnt-instance stop $INSTANCE
    #
    # STEP 13. switch to DRBD, still on the Ganeti MASTER NODE:
    #
    #         gnt-instance modify -t drbd $INSTANCE
    #         gnt-instance failover -f $INSTANCE
    #         gnt-instance startup $INSTANCE
    #
    # STEP 14, 15, 16 delegated to renumber-instance
    #
    # STEP 17. decomission old instance ([[retire-a-host]])
