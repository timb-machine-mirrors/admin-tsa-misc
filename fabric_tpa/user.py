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

import getpass
import logging
import os.path
import sys

try:
    from fabric import task
except ImportError:
    sys.stderr.write(
        "cannot find fabric, install with `apt install python3-fabric`\n"
    )
    raise

try:
    import ldap
except ImportError:
    sys.stderr.write(
        "cannot find Python LDAP, install with `apt install python3-ldap`\n"
    )
    raise


class LdapContext(object):
    def __init__(self, uri):
        self.uri = uri
        self.ldap = ldap.initialize(uri)
        # TODO: certificate might expire, check for expiry and renew
        # if necessary
        self.ldap.set_option(
            ldap.OPT_X_TLS_CACERTFILE,
            os.path.dirname(__file__) + "/db.torproject.org.pem",
        )
        # default, but just making sure
        self.ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_HARD)

    def bind(self, dn=None, password=None):
        if dn is None:
            dn = "uid=%s,ou=users,dc=torproject,dc=org" % getpass.getuser()
        if password is None:
            password = getpass.getpass(
                prompt="%s LDAP password for %s: " % (self.uri, dn)
            )
        self.ldap.simple_bind_s(dn, password)
        self.dn = dn

    def __str__(self):
        return "LdapContext(%r, %r, %r): %s" % (
            self.uri,
            self.dn,
            "[CENSORED]",
            self.ldap,
        )


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


def parse_ldap_result_user(dn, result):
    uid = result["uid"][0].decode("utf-8")
    uidNumber = result["uidNumber"][0].decode("utf-8")
    gidNumber = result["gidNumber"][0].decode("utf-8")
    groups = [g.decode("utf-8") for g in result["supplementaryGid"]]
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
    if "adm" in groups:
        yield "ldap-admin"
    if "torproject" in groups:
        yield "login-everywhere"


flags_meaning = {
    "ldap-admin": "has root and LDAP admin (adm group)",
    "login-everywhere": "has SSH access everywhere (torproject group)",
    "gid-mismatch": "uid and gid do not match, might have extra access",
}


@task
def audit_ldap(
    con, user="*", ldap_uri="ldaps://db.torproject.org", dn=None, password=None
):
    """look for privileges of the given user on LDAP

    By default dumps all the users from LDAP. """
    con = LdapContext(ldap_uri)
    con.bind(dn, password)
    logging.info("dumping valid users")
    # except ldap.LDAPError as e:
    logging.debug("connected to %s", con)
    filter = "(&%s%s)" % (LDAP_VALID_USERS_FILTER, "(uid=%s)" % user)
    # this header must match the f-string in parse_ldap_result_user()
    print("uid\tflags\tgroups")
    for dn, result in con.ldap.search_s(
        base="ou=users,dc=torproject,dc=org", scope=ldap.SCOPE_SUBTREE, filterstr=filter
    ):
        logging.debug("dn: %s, dump: %s" % (dn, result))
        info, flags = parse_ldap_result_user(dn, result)
        print(info)
        for flag in flags:
            logging.warning(
                "%s: %s", flag, flags_meaning.get(flag, "NO MEANING DEFINED")
            )
