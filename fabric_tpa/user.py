#!/usr/bin/python3
# coding: utf-8

"""user management fabric library

The goal of this library is to cover user creation and removal.

It should go through the following services when creating or removing
a user.

https://trac.torproject.org/projects/tor/wiki/org/operations/services

For now it only does LDAP.
"""
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

import logging
import sys

try:
    from fabric import task
except ImportError:
    sys.stderr.write(
        "cannot find fabric, install with `apt install python3-fabric`\n"
    )
    raise

from . import LdapContext

LDAP_VALID_USERS_FILTER = """
(&
  (!
    (|
      (objectclass=debianRoleAccount)
      (objectClass=debianGroup)
      (objectClass=simpleSecurityObject)
      (shadowExpire=1)
    )
  )
  (objectClass=debianAccount)
)""".replace(
    "\n", ""
).replace(
    " ", ""
)


def parse_ldap_result_user(con, dn, result):
    uid = result["uid"][0].decode("utf-8")
    uidNumber = result["uidNumber"][0].decode("utf-8")
    gidNumber = result["gidNumber"][0].decode("utf-8")

    groups = [g.decode("utf-8") for g in result["supplementaryGid"]]
    # also look for membership in other users, this mostly covers the
    # "LDAP Administrator" "group" (which is really a user, because
    # it's in "ou=users"!)
    for dn, result in con.search_users("(member=%s)" % dn):
        groups.append(result["cn"][0].decode("utf-8"))

    groups_str = ",".join(groups)
    flags = list(groups_to_flags(groups))
    # TODO: we should also check the gid resolves to the same group
    # name as the username
    if uidNumber != gidNumber:
        flags.append("gid-mismatch")
    flags_str = ",".join(flags)
    # must f-string match the header in audit_ldap()
    return f"{uid}\t{flags_str}\t{groups_str}", flags


def groups_to_flags(groups):
    """parse the list of groups and generate meaningful flags"""
    if "LDAP administrator" in groups:
        yield "ldap-admin"
    if "adm" in groups:
        yield "root-adm"
    if "torproject" in groups:
        yield "login-everywhere"


flags_meaning = {
    "ldap-admin": "has LDAP admin",
    "root-adm": "has root (adm group)",
    "login-everywhere": "has SSH access everywhere (torproject group)",
    "gid-mismatch": "uid and gid do not match, might have extra access",
}


@task
def audit_ldap(con, user="*"):
    """look for privileges of the given user on LDAP

    By default dumps all the users from LDAP. """
    con = LdapContext().bind()
    logging.info("dumping valid users")
    # except ldap.LDAPError as e:
    logging.debug("connected to %s", con)
    filter = "(&%s%s)" % (LDAP_VALID_USERS_FILTER, "(uid=%s)" % user)
    # this header must match the f-string in parse_ldap_result_user()
    print("uid\tflags\tgroups")
    for dn, result in con.search_users(filter):
        logging.debug("dn: %s, dump: %s" % (dn, result))
        info, flags = parse_ldap_result_user(con, dn, result)
        print(info)
        for flag in flags:
            logging.warning(
                "%s: %s", flag, flags_meaning.get(flag, "NO MEANING DEFINED")
            )


@task
def audit_group(con, group):
    """look for the privileges of the given group in LDAP and list its members"""
    con = LdapContext().bind()
    filter = "(&%s%s)" % (LDAP_VALID_USERS_FILTER, "(supplementaryGid=%s)" % group)
    users = []
    for _, result in con.search_users(filter):
        user = result["uid"][0].decode("utf-8")
        # XXX: this does not work, because slapd's ACL block that from
        # view remotely.
        if result.get("sshRSAAuthKey"):
            user += "*"
        users.append(user)
    print("member users:", *sorted(users))
    filter = '(allowedGroups=%s)' % group
    hosts = [result["hostname"][0].decode("utf-8")
             for dn, result in con.search_hosts(filter)]
    print("accessible hosts:", *sorted(hosts))
    print("I: star (*) denotes users with an SSH key")
    print("W: users may access other hosts through other mechanism like exportOptions")

@task
def list_gaps(con):
    """list gaps in the UID or GID allocations"""
    con = LdapContext().bind()
    filter = "(|(objectClass=debianAccount)(objectClass=debianGroup))"

    users = []
    groups = []
    for _, result in con.search_users(filter):
        uid = result.get("uid")
        gid = result.get("gid")
        if uid is not None: # a user
            users.append(int(result.get("uidNumber")[0].decode("utf-8")))
        if gid is not None: # a group
            groups.append(int(result.get("gidNumber")[0].decode("utf-8")))

    prev_user = None
    for user in sorted(users):
        if prev_user is not None and user - prev_user > 1:
            print("gap between uid %d and %d" % (prev_user, user))
        prev_user = user

    prev_group = None
    for group in sorted(groups):
        if prev_group is not None and group - prev_group > 1:
            print("gap between gid %d and %d" % (prev_group, group))
        prev_group = group
