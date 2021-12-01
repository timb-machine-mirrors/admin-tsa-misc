#!/usr/bin/python3
# coding: utf-8

'''retirement procedures'''
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
import invoke.exceptions

from . import libvirt
from . import host
from . import ganeti


# see also https://help.torproject.org/tsa/howto/retire-a-host/


@task
def retire_instance(instance_con, parent_host):
    '''retire instance, depending on its type

    Checks if it's a ganeti node and otherwise assunmes it's
    libvirt...

    TODO: to be expanded to cover for physical machines
    '''
    host_con = host.find_context(parent_host, config=instance_con.config)
    try:
        master_con = ganeti.getmaster(host_con)
    except invoke.exceptions.Failure:
        libvirt.retire(instance_con, host_con)
    else:
        ganeti.retire(instance_con, master_con)


@task
def remove_backups(instance_con, backup_host, backup_director_host):
    '''delete instance backups from the bacula storage host'''
    for backup_dir in (
            '/srv/backups/bacula/%s/' % instance_con.host,
            '/srv/backups/pg/%s/' % instance_con.host.split(".")[0],
    ):
        backup_con = host.find_context(backup_host, config=instance_con.config)
        if host.path_exists(backup_con, backup_dir):
            host.schedule_delete(backup_con, backup_dir, '30 days')

    con = host.find_context(backup_director_host, config=instance_con.config)
    command = 'delete client=%s' % instance_con.host
    host.schedule_job(con, command, '30 days')


@task
def revoke_puppet(instance_con, puppetmaster='root@puppet.torproject.org'):
    '''revoke certificates of given instance on puppet master'''
    con = host.find_context(puppetmaster, config=instance_con.config)
    # XXX: error handling?
    con.run('puppet node clean %s' % instance_con.host)
    con.run('puppet node deactivate %s' % instance_con.host)
    con.run('service apache2 restart')   # reload the CRL
    # reload puppetdb so it knows about the deactivation
    con.run('service puppetdb restart')


@task
def retire_all(instance_con,
               parent_host=None,
               backup_host='bungei.torproject.org',
               backup_director_host='bacula-director-01.torproject.org',
               puppet_host='root@puppet.torproject.org'):
    '''retire an instance from its parent, backups and puppet'''
    # STEP 1, 3, 4, 5
    if parent_host:
        try:
            retire_instance(instance_con, parent_host)
        except invoke.exceptions.Failure as e:
            logging.error('failed to retire instance %s on host %s: %s',
                          instance_con.host, parent_host, e)
            return 1
    else:
        logging.warning('not wiping instance %s data: no parent host',
                        instance_con.host)
        # TODO: destroy actual on-disk data
    # STEP 13
    if backup_host:
        logging.info('scheduling %s backup disks removal on host %s and director %s',
                     instance_con.host, backup_host, backup_director_host)
        try:
            remove_backups(instance_con, backup_host, backup_director_host)
        except invoke.exceptions.Failure as e:
            logging.error('failed to remove %s backups on host %s and director %s: %s',
                          instance_con.host, backup_host, backup_director_host, e)
            return 2
    # STEP 8
    if puppet_host:
        try:
            revoke_puppet(instance_con, puppet_host)
        except invoke.exceptions.Failure as e:
            logging.error('failed to revoke instance %s on host %s: %s',
                          puppet_host, instance_con.host, e)
            return 3
    # missing:
    # STEP 2: nagios
    # STEP 6: LDAP
    # STEP 7: DNS
    # STEP 9: Puppet source
    # STEP 10: tor-passwords
    # STEP 11: let's encrypt
    # STEP 12: DNSWL
    # STEP 14: docs
    # STEP 15: upstream decommissioning
