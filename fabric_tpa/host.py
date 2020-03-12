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


@task
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
def append_to_file(con, path, content):
    '''append bytes to a file

    This does not check for duplicates.'''
    if con.config.run.dry:
        return
    with con.sftp().file(path, mode='ab') as fp:
        fp.write(content)


@task
def ensure_line(con, path, line):
    if con.config.run.dry:
        return
    with con.sftp().file(path, mode='w+b') as fp:
        ensure_line_stream(fp, line)


def ensure_line_stream(stream, line, match=None, ensure_line=True):
    '''ensure that line is present in the given stream, adding it if missing

    Will ensure the given line is present in the stream. If match is
    provided, it's treated as a regular expression for a pattern to
    look for. It will *not* replace the line matching the pattern,
    just look for it. If match is not provided, it defaults to the
    full line on its own line.

    If ensure_line is specified (the default), it will also append a
    newline character even if missing from the line.

    This is inspired by Puppet's stdlib file_line resource:

    https://github.com/puppetlabs/puppetlabs-stdlib/'''
    if match is None:
        match = b'^' + line + b'$'
    rep = re.compile(match, flags=re.MULTILINE)
    if ensure_line and not line.endswith(b"\n"):
        line += b"\n"
    stream.seek(0)
    # TODO: loads entire file in memory, could be optimized
    if rep.search(stream.read()):
        logging.debug('line present in stream %s, skipping: %s',
                      stream, line)
    else:
        logging.debug('line not found in stream %s, appending: %s',
                      stream, line)
        stream.seek(0, 2)  # EOF
        stream.write(line)
    return stream


def test_ensure_line_stream():
    '''test for ensure_line_stream'''
    import io
    stream = io.BytesIO()
    ensure_line_stream(stream, b"// test", ensure_line=False)
    assert stream.seek(0) == 0
    assert stream.read() == b"// test"
    stream = io.BytesIO()
    ensure_line_stream(stream, b"// test")
    assert stream.seek(0) == 0
    assert stream.read() == b"// test\n"
    ensure_line_stream(stream, b"test")
    stream.seek(0)
    assert stream.read() == b"// test\ntest\n"
    stream = io.BytesIO(b"// test\n")
    ensure_line_stream(stream, b"test", match=b"^.*test.*$")
    stream.seek(0)
    assert stream.read() == b"// test\n"


@task
def rewrite_file(con, path, content):
    '''write a new file, keeping a backup

    This overwrites the given PATH with CONTENT, keeping a backup in a
    .bak file and showing a diff.
    '''
    backup_path = path + '.bak'
    logging.info('renaming %s to %s on %s', path, backup_path, con.host)
    if not con.config.run.dry:
        con.sftp().rename(path, backup_path)
    logging.info('writing file %d bytes in %s on %s',
                 len(content), path, con.host)
    append_to_file(con, path, content)
    res = con.run('diff -u %s %s' % (backup_path, path))
    logging.debug('file diff: %s', res.stdout)


@task
def rewrite_interfaces(con, ipconfig=(),
                       path='/etc/network/interfaces'):
    '''write an /etc/network/interfaces file

    This writes the given ipconfig namedtuple into the given
    interfaces(5) file, keeping a backup (uses rewrite-file).
    '''
    content = f'''# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).

# The loopback network interface
auto lo
iface lo inet loopback

# The primary network interface
auto eth0
iface eth0 inet static
    address {ipconfig.ipv4}/{ipconfig.ipv4_subnet}
    gateway {ipconfig.ipv4_gateway}
iface eth0 inet6 static
    accept_ra 0
    address {ipconfig.ipv6}/{ipconfig.ipv6_subnet}
    gateway {ipconfig.ipv6_gateway}
'''
    logging.debug('generated %s: %s', path, content)
    rewrite_file(con, path, content)


@task
def mount(con, device, path, options='', warn=None):
    '''mount a device'''
    command = 'mount %s %s %s' % (device, path, options)
    return con.run(command, warn=warn)


@task
def umount(con, path):
    '''umount a device'''
    return con.run('umount %s' % path)


@contextmanager
def mount_then_umount(con, device, path, options='', warn=None):
    '''convenient context manager for mount/umount'''
    try:
        yield mount(con, device, path, options, warn)
    finally:
        return umount(con, path)


ipconfig = namedtuple('ipconfig', 'ipv4 ipv4_subnet ipv4_gateway ipv6 ipv6_subnet ipv6_gateway')  # noqa: E501


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
