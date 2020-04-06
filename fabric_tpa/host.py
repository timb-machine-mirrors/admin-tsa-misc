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

from collections import namedtuple
from contextlib import contextmanager
import io
import logging
import os.path
from pathlib import Path
import re
import sys


try:
    from fabric import task, Connection
except ImportError:
    sys.stderr.write('cannot find fabric, install with `apt install python3-fabric`')  # noqa: E501
    raise
import invoke.exceptions


@task
def path_exists(host_con, path):
    '''check if path exist with SFTP'''
    logging.info('checking for path "%s" on %s', path, host_con.host)
    sftp = host_con.sftp()
    try:
        sftp.chdir(path)
    except IOError as e:
        logging.error('path %s not found: %s', path, e)
        return False
    return True


@task
def schedule_delete(host_con, path, delay):
    '''schedule removal of PATH in the future

    The job is scheduled with `at(1)` so the DELAY is interpreted
    accordingly. Normally, it should be something like "7 days".
    '''

    # TODO: shell escapes?
    command = 'rm -rf "%s"' % path
    logging.info('scheduling %s to run on %s in %s',
                 command, host_con.host, delay)
    return host_con.run("echo '%s' | at now + %s" % (command, delay),
                        warn=True).ok


@task(autoprint=True)
def fetch_ssh_host_pubkey(con, type='ed25519'):
    '''fetch public host key from server'''
    buffer = io.BytesIO()
    pubkey_path = '/etc/ssh/ssh_host_%s_key.pub' % type
    try:
        con.get(pubkey_path, local=buffer)
    except OSError as e:
        logging.error('cannot fetch instance config from %s: %s',
                      pubkey_path, e)
        return False
    return buffer.getvalue()


@task
def write_to_file(con, path, content, mode='wb'):
    _write_to_file(con, path, content, mode=mode)


def _write_to_file(con, path, content, mode='wb'):
    '''append bytes to a file

    This does not check for duplicates.'''
    if con.config.run.dry:
        return
    with con.sftp().file(path, mode=mode) as fp:
        fp.write(content)


@task
def ensure_line(con, path, line, match=None, ensure_newline=True):
    if con.config.run.dry:
        return
    with con.sftp().file(path, mode='ab+') as fp:
        ensure_line_stream(fp, line, match=match, ensure_newline=ensure_newline)


def ensure_line_stream(stream, line,
                       match=None,
                       ensure_newline=True,
                       flags=re.MULTILINE):
    '''ensure that line is present in the given stream, adding it if missing

    Will ensure the given line is present in the stream. If match is
    provided, it's treated as a regular expression for a pattern to
    look for. It will *not* replace the line matching the pattern,
    just look for it. If match is not provided, it defaults to the
    full line on its own line.

    If ensure_newline is specified (the default), it will also append a
    newline character even if missing from the line.

    This is inspired by Puppet's stdlib file_line resource:

    https://github.com/puppetlabs/puppetlabs-stdlib/'''
    if match is None:
        match = b'^' + re.escape(line) + b'$'
    rep = re.compile(match, flags=flags)
    stream.seek(0)
    # TODO: loads entire file in memory, could be optimized
    content = stream.read()
    res = rep.search(content)
    if res:
        if res.group(0).strip() == line.strip():
            logging.debug('exact line present in stream %s, skipping: %s',
                          stream, line)
        else:
            logging.debug('match found in stream %s: %s; replacing with %s',
                          stream, res.group(0), line)
            stream.seek(0)
            content_new = rep.sub(line, content)
            logging.debug('before: %s; after: %s', content, content_new)
            stream.seek(0)
            stream.truncate(0)
            stream.write(content_new)
    else:
        logging.debug('line not found in stream %s, appending: %s',
                      stream, line)
        stream.seek(0, 2)  # EOF
        stream.write(line)

        # append newline only if the line is totally missing, because
        # otherwise if we replace an existing line the regex doesn't
        # match the newline (unless the caller passes flags=DOTALL, in
        # which case they are responsible for the trouble they're
        # in. see ensure_ssh_key_stream() for what "trouble" looks
        # like.
        if ensure_newline and not line.endswith(b"\n"):
            stream.write(b"\n")
    return stream


def test_ensure_line_stream():
    '''test for ensure_line_stream'''
    import io

    stream = io.BytesIO()
    ensure_line_stream(stream, b"// test", ensure_newline=False)
    assert stream.seek(0) == 0
    assert stream.read() == b"// test", 'appends if empty, without newline'

    stream = io.BytesIO()
    ensure_line_stream(stream, b"// test")
    assert stream.seek(0) == 0
    assert stream.read() == b"// test\n", 'appends if empty, with newline'
    ensure_line_stream(stream, b"test")
    stream.seek(0)
    assert stream.read() == b"// test\ntest\n", 'appends if not full match'

    stream = io.BytesIO(b"// test\n")
    ensure_line_stream(stream, b"// test", match=b"^.*test.*$")
    stream.seek(0)
    assert stream.read() == b"// test\n", 'does not append on partial'

    ensure_line_stream(stream, b"test", match=b"^.*test.*$")
    stream.seek(0)
    assert stream.read() == b"test\n", 'replaces on partial'

    header = b"""# HEADER: This file was autogenerated at 2020-03-24 22:35:16 +0000
# HEADER: by puppet.  While it can still be managed manually, it
# HEADER: is definitely not recommended.
"""
    key = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIyMtFIII1NEokPxlDfa6Sx2evW3+xvtzziso81aVqJf root@fsn-node-05.torproject.org"  # noqa: E501
    key_comment = b"# fsn-node-05.torproject.org pubkey for forrestii.torproject.org transfer"  # noqa: E501

    key_blob = key_comment + b"\n" + key

    stream = io.BytesIO(header)
    ensure_line_stream(stream, key_blob,
                       match=br"(?:^#[^\n]*$)?\s+" + re.escape(key) + b'$')
    stream.seek(0)
    assert stream.read() == header + key_blob + b"\n"
    ensure_line_stream(stream, key_blob,
                       match=br"(?:^#[^\n]*$)?\s+" + re.escape(key) + b'$')
    stream.seek(0)
    assert stream.read() == header + key_blob + b"\n"


@task
def ensure_ssh_key(con, path, key, comment=None):
    if con.config.run.dry:
        return
    with con.sftp().file(path, mode='ab+') as fp:
        ensure_ssh_key_stream(fp, key, comment)


def ensure_ssh_key_stream(stream, key, comment=None):
    if comment is None:
        match = None
        key_blob = key
    else:
        match = br"(?:^#[^\n]*$)?\s+" + re.escape(key) + b'$'
        key_blob = comment + b"\n" + key
    ensure_line_stream(stream, key_blob, match=match, flags=re.MULTILINE | re.DOTALL)


def test_ensure_ssh_key():
    header = b"""# HEADER: This file was autogenerated at 2020-03-24 22:35:16 +0000
# HEADER: by puppet.  While it can still be managed manually, it
# HEADER: is definitely not recommended.
# This is some sample key that should be preserved
ssh-rsa SOME KEY
"""
    key = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIyMtFIII1NEokPxlDfa6Sx2evW3+xvtzziso81aVqJf root@fsn-node-05.torproject.org"  # noqa: E501
    key_comment = b"# fsn-node-05.torproject.org pubkey for forrestii.torproject.org transfer"  # noqa: E501

    stream = io.BytesIO(header)
    ensure_ssh_key_stream(stream, key, key_comment)
    stream.seek(0)
    assert stream.read() == header + key_comment + b"\n" + key + b"\n"
    ensure_ssh_key_stream(stream, key, key_comment)
    stream.seek(0)
    assert stream.read() == header + key_comment + b"\n" + key + b"\n"


@task
def backup_file(con, path):
    _backup_file(con, path)


def _backup_file(con, path):
    backup_path = path + '.bak'
    logging.info('copying %s to %s on %s', path, backup_path, con.host)
    if not con.config.run.dry:
        res = con.run('cp %s %s' % (path, backup_path), warn=True)
        if res.failed:
            logging.warning('failed backup file %s, assuming backup is current', path)
    return backup_path


@task
def diff_file(con, left_path, right_path):
    return _diff_file(con, left_path, right_path)


def _diff_file(con, left_path, right_path):
    return con.run('diff -u %s %s' % (left_path, right_path), warn=True)


@task
def rewrite_file(con, path, content):
    _rewrite_file(con, path, content)


def _rewrite_file(con, path, content):
    '''write a new file, keeping a backup

    This overwrites the given PATH with CONTENT, keeping a backup in a
    .bak file and showing a diff.
    '''
    backup_path = _backup_file(con, path)
    logging.info('writing file %d bytes in %s on %s',
                 len(content), path, con.host)
    _write_to_file(con, path, content)
    return _diff_file(con, backup_path, path)


@task
def rewrite_interfaces(con,
                       ipv4_address, ipv4_subnet, ipv4_gateway,
                       ipv6_address, ipv6_subnet, ipv6_gateway,
                       path='/etc/network/interfaces'):
    '''write an /etc/network/interfaces file

    This writes the given ifconfig namedtuple into the given
    interfaces(5) file, keeping a backup (uses rewrite-file).
    '''
    # TODO: do SLAAC based on ipv6_net?
    ipconf = ifconfig(ipv4_address, ipv4_subnet, ipv4_gateway,
                      ipv6_address, ipv6_subnet, ipv6_gateway)
    return rewrite_interfaces_ifconfig(con, ipconf, path)


def rewrite_interfaces_ifconfig(con, ipconf, path='/etc/network/interfaces'):
    content = f'''# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).

# The loopback network interface
auto lo
iface lo inet loopback

# The primary network interface
auto eth0
iface eth0 inet static
    address {ipconf.ipv4}/{ipconf.ipv4_subnet}
    gateway {ipconf.ipv4_gateway}
'''

    if ipconf.ipv6:
        content += f'''
# IPv6 configuration
iface eth0 inet6 static
    accept_ra 0
    address {ipconf.ipv6}/{ipconf.ipv6_subnet}
    gateway {ipconf.ipv6_gateway}
'''
    logging.debug('generated %s: %s', path, content)
    return _rewrite_file(con, path, content)


@task
def rewrite_hosts(con, fqdn, ipv4_address, ipv6_address=None, path='/etc/hosts'):
    _rewrite_hosts(con, fqdn, ipv4_address, ipv6_address, path)


def _rewrite_hosts(con, fqdn, ipv4_address, ipv6_address=None, path='/etc/hosts'):
    backup_path = _backup_file(con, path)
    if con.config.run.dry:
        logging.info('skipping hosts file rewriting in dry run')
        return
    logging.info('rewriting host file %s on %s', path, con)
    with con.sftp().file(path, mode='ab+') as fp:
        rewrite_hosts_file(fp,
                           fqdn.encode('ascii'),
                           ipv4_address.encode('ascii'),
                           ipv6_address.encode('ascii') if ipv6_address else None)
    _diff_file(con, backup_path, path)


def rewrite_hosts_file(stream, fqdn, ipv4_address, ipv6_address=None):
    hostname, _ = fqdn.split(b'.', 1)
    line = b'%s %s %s' % (ipv4_address, fqdn, hostname)
    logging.debug('ensuring %s in hosts file', line)
    ensure_line_stream(stream, line,
                       match=br'^[.\d]+\s+' + re.escape(fqdn) + br'\b.*$')
    if ipv6_address is not None:
        line = b'%s %s %s' % (ipv6_address, fqdn, hostname)
        logging.debug('ensuring %s in hosts file', line)
        ensure_line_stream(stream, line,
                           match=br'^[:0-9a-fA-F]+\s+'
                           + re.escape(fqdn)
                           + br'\b.*$')


def test_rewrite_hosts_file():
    import io
    stream = io.BytesIO()
    i = b'1.2.3.4'
    rewrite_hosts_file(stream, b'test.example.com', i)
    stream.seek(0)
    assert stream.read() == b"1.2.3.4 test.example.com test\n"
    rewrite_hosts_file(stream, b'test.example.com', i)
    stream.seek(0)
    assert stream.read() == b"1.2.3.4 test.example.com test\n"
    i = b'1.2.3.5'
    rewrite_hosts_file(stream, b'test.example.com', i)
    stream.seek(0)
    assert stream.read() == b"1.2.3.5 test.example.com test\n"

    stream = io.BytesIO(b"# this is a hosts file\n138.201.212.234        forrestii.torproject.org forrestii\n")  # noqa: E501
    rewrite_hosts_file(stream, b'forrestii.torproject.org', i)
    stream.seek(0)
    assert stream.read() == b"# this is a hosts file\n1.2.3.5 forrestii.torproject.org forrestii\n"  # noqa: E501

    stream = io.BytesIO(b"138.201.212.234\tforrestii.torproject.org\tforrestii\n")
    rewrite_hosts_file(stream, b'forrestii.torproject.org', i)
    stream.seek(0)
    assert stream.read() == b"1.2.3.5 forrestii.torproject.org forrestii\n"

    stream = io.BytesIO(b"::1\tforrestii.torproject.org\tforrestii\n")
    rewrite_hosts_file(stream, b'forrestii.torproject.org', i)
    stream.seek(0)
    assert stream.read() == b"::1\tforrestii.torproject.org\tforrestii\n1.2.3.5 forrestii.torproject.org forrestii\n"  # noqa: E501

    stream = io.BytesIO(b"::1\tforrestii.torproject.org\tforrestii\n")
    rewrite_hosts_file(stream, b'forrestii.torproject.org', i, b'fe80::')
    stream.seek(0)
    assert stream.read() == b"fe80:: forrestii.torproject.org forrestii\n1.2.3.5 forrestii.torproject.org forrestii\n"  # noqa: E501


@task
def mount(con, device, path, options='', warn=None):
    '''mount a device'''
    command = 'mount %s %s %s' % (device, path, options)
    # XXX: error handling?
    return con.run(command, warn=warn)


@task
def umount(con, path):
    '''umount a device'''
    # XXX: error handling?
    return con.run('umount %s' % path)


@contextmanager
def mount_then_umount(con, device, path, options='', warn=None):
    '''convenient context manager for mount/umount'''
    try:
        yield mount(con, device, path, options, warn)
    finally:
        umount(con, path)


ifconfig = namedtuple('ifconfig', 'ipv4 ipv4_subnet ipv4_gateway ipv6 ipv6_subnet ipv6_gateway')  # noqa: E501


@task
def ipv6_slaac(con, ipv6_subnet, mac, hide=True, dry=False):
    '''compute IPv6 SLAAC address from subnet and MAC address

    This uses the ipv6calc command.

    .. TODO:: rewrite in python-only?
    '''
    command = ['ipv6calc', '--action', 'prefixmac2ipv6',
               '--in', 'prefix+mac', '--out', 'ipv6',
               ipv6_subnet, mac]
    logging.debug('manual SLAAC allocation with: %s', ' '.join(command))
    try:
        # XXX: error handling?
        return con.run(' '.join(command), hide=hide, dry=dry).stdout.strip()
    except invoke.exceptions.UnexpectedExit as e:
        logging.error('cannot find IPv6 address, install ipv6calc: %s', e)


def test_ipv6_slaac():
    con = invoke.Context()
    mac = '00:66:37:f1:bb:6b'
    network = '2a01:4f8:fff0:4f::'
    expected = '2a01:4f8:fff0:4f:266:37ff:fef1:bb6b'
    assert expected == ipv6_slaac(con, network, mac)


def find_context(hostname, config=None):
    if isinstance(hostname, (Connection, invoke.Context)):
        return hostname
    else:
        return Connection(hostname, config=config)


@task
def install_hetzner_robot(con,
                          fqdn,
                          fai_disk_config,
                          package_list,
                          post_scripts_dir):
    '''install a new hetzner server

    As an exception, the `--hosts` (`-H`) argument *must* be the IP
    address here. The actual hostname, provided as an argument, will
    be *set* on the host.
    '''
    # TODO: do not hardcode
    boot_disks = ['/dev/nvme0n1']
    # TODO: automatically guess package_list and post_scripts_dir
    # based on current path

    # summary of the new-machine-hetzner-robot procedure:
    #
    # STEP 1: login over SSH, checking fingerprint
    # STEP 2: set hostname
    # STEP 3: partition disks
    # STEP 4: run grml-debootstrap with packages and post-scripts
    # STEP 5: setup dropbear-initramfs (in the post-scripts)
    # STEP 6: crypto config
    # STEP 7: network config
    # STEP 8: regenerate initramfs if relevant
    # STEP 9: unmount
    # STEP 10: close volumes
    # STEP 11: document root password
    # STEP 12: reboot

    # STEP 1: TODO: wrap this function with a magic Con object that
    # will check the fingerprint properly

    # STEP 2
    hostname, _ = fqdn.split('.', 1)
    logging.info('setting hostname to %s', hostname)
    # XXX: error handling?
    con.run('hostname %s' % hostname)

    sftp = con.sftp()

    # keep trailing slash
    remote_conf_path = '/etc/tpa-installer/'
    try:
        sftp.mkdir(remote_conf_path)
    except OSError as e:
        # ignore existing directory
        #
        # XXX: SFTP doesn't really help us distinguish between real
        # and "EEXIST" errors, it just returns an error code 4
        # ("SSH_FX_FAILURE") if the directory exists
        if 'Failure' in str(e):
            pass

    # STEP 3
    fai_disk_config_remote = remote_conf_path + os.path.basename(fai_disk_config)
    logging.info('deploying disk config %s to %s',
                 fai_disk_config, fai_disk_config_remote)
    con.put(fai_disk_config, remote=fai_disk_config_remote)

    logging.info('installing fai-setup-storage(8)')
    # XXX: error handling?
    con.run('apt update && apt install -y fai-setup-storage')

    # the rationale here is that some of the dependencies we need
    # might have security vulnerabilities, and i have found the rescue
    # images sometimes don't have the latest
    logging.info('running upgrades')
    # XXX: error handling?
    con.run('apt upgrade -yy')

    logging.info('partitionning disks')
    # XXX: error handling?
    con.run("setup-storage -f '%s' -X" % fai_disk_config_remote)

    # TODO: test if we can skip that test by passing `$ROOT_PARTITION`
    # as a `--target` to `grml-debootstrap`. Probably not.
    logging.info('mounting partitions from FAI')
    # TODO: parse the .sh file ourselves?
    # XXX: error handling?
    con.run('. /tmp/fai/disk_var.sh && mkdir /target && mount "$ROOT_PARTITION" /target && mkdir /target/boot && mount "$BOOT_DEVICE" /target/boot')  # noqa: E501

    # STEP 4: run grml-debootstrap with packages and post-scripts
    logging.info('uploading package list %s', package_list)
    package_list_remote = remote_conf_path + os.path.basename(package_list)
    con.put(package_list, remote=package_list_remote)

    # TODO: those post-scripts *could* be turned into one nice fabric
    # recipe instead, after all we still have access to the chroot
    # after and know what we need to do at the end (ie. rebuild
    # initramfs and install grub)
    post_scripts_dir_remote = remote_conf_path + 'post-scripts/'
    logging.info('uploading post-scripts %s to %s',
                 post_scripts_dir, post_scripts_dir_remote)
    try:
        sftp.mkdir(post_scripts_dir_remote)
    except OSError as e:
        # ignore existing directory, see earlier XXX
        if 'Failure' in str(e):
            pass
    for post_script in Path(post_scripts_dir).iterdir():
        filename = str(post_script.resolve())
        remote = post_scripts_dir_remote + os.path.basename(filename)
        logging.debug('uploading %s to %s', filename, remote)
        con.put(filename, remote=remote)

    logging.info('installing grml-debootstrap')
    # XXX: error handling?
    con.run('apt-get install -y grml-debootstrap')

    logging.info('setting up grml-debootstrap')
    # XXX: error handling?
    con.run('''mkdir -p /target/run && \
        mount -t tmpfs tgt-run /target/run && \
        mkdir /target/run/udev && \
        mount -o bind /run/udev /target/run/udev''')
    # TODO: do we really need grml-deboostrap here? why not just use
    # plain debootstrap?
    logging.info('running grml-debootstrap')
    installer = '''. /tmp/fai/disk_var.sh && \
        AUTOINSTALL=y grml-debootstrap \
            --grub "%s" \
            --target /target \
            --hostname `hostname` \
            --release buster \
            --mirror https://mirror.hetzner.de/debian/packages/ \
            --packages %s \
            --post-scripts %s \
            --nopassword \
            --remove-configs \
            --defaultinterfaces''' % (
            boot_disks[0],
            package_list_remote,
            post_scripts_dir_remote,
        )
    try:
        # XXX: error handling?
        con.run(installer)
    except Exception as e:
        logging.error('installer failed: %s', e)
    # XXX: error handling?
    con.run('umount /target/run/udev /target/run || true')

    # TODO: extract the resulting SSH keys and inject in a local
    # known_hosts for further bootstrapping. e.g.:
    logging.info('dumping SSH keys')
    # XXX: error handling?
    con.run('cat /target/etc/ssh/ssh_host_*.pub')
    con.run('for key in /target/etc/dropbear-initramfs/dropbear_*_host_key; do'
            'dropbearkey -y -f $key; done')

    # STEP 5
    logging.info('locking down /target/etc/luks')
    # XXX: error handling?
    con.run('chmod 0 /target/etc/luks/')

    # STEP 6
    # XXX: error handling?
    con.run('cat /target/etc/crypttab')

    # STEP 7
    # XXX: error handling?
    con.run('cat /target/etc/network/interfaces')
    # TODO: setup interfaces correctly

    # STEP 8: rebuild initramfs and grub (TODO?)
    # STEP 9: unmount things
    # XXX: error handling?
    con.run('umount /target/dev /target/proc /target/sys || true')
    con.run('umount /target/boot /target || true')
    con.run('rmdir /target')

    # STEP 10: close things
    # XXX: error handling?
    con.run('vgchange -a n')
    # TODO: crypt_dev_md2?
    con.run('cryptsetup luksClose /dev/mapper/crypt_dev_md1')
    con.run('mdadm --stop /dev/md*')

    # STEP 11: document LUKS and root password in pwmanager (TODO)
    # STEP 12: reboot (TODO)
    # XXX: error handling?
    con.run('reboot machine when happy: ./reboot -H root@%s -v --reason "new-machine procedure" --delay-shutdown 0' % con.host)  # noqa: E501
