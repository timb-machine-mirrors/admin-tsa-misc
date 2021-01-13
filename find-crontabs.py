#!/usr/bin/python3
# coding: utf-8

"""short test of mitogen"""
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

import argparse
import logging
import os.path
import sys

import mitogen
import mitogen.utils
from mitogen.select import Select


class LoggingAction(argparse.Action):
    """change log level on the fly

    The logging system should be initialized befure this, using
    `basicConfig`.
    """

    def __init__(self, *args, **kwargs):
        """setup the action parameters

        This enforces a selection of logging levels. It also checks if
        const is provided, in which case we assume it's an argument
        like `--verbose` or `--debug` without an argument.
        """
        kwargs["choices"] = logging._nameToLevel.keys()
        if "const" in kwargs:
            kwargs["nargs"] = 0
        super().__init__(*args, **kwargs)

    def __call__(self, parser, ns, values, option):
        """if const was specified it means argument-less parameters"""
        if self.const:
            logging.getLogger("").setLevel(self.const)
        else:
            logging.getLogger("").setLevel(values)


def parse_args(args=sys.argv[1:]):
    parser = argparse.ArgumentParser(description=__doc__, epilog="""TODO""")
    parser.add_argument(
        "--verbose", "-v", dest="log_level", action=LoggingAction, const="INFO"
    )
    parser.add_argument(
        "--debug", "-d", dest="log_level", action=LoggingAction, const="DEBUG"
    )
    parser.add_argument("--dryrun", "-n", action="store_true", help="do nothing")
    parser.add_argument("--user", "-u", required=True, help="username")
    parser.add_argument(
        "--hosts", "-H", nargs="+", required=True, help="hosts to check"
    )
    return parser.parse_args(args=args)


def hunt_crontab(user):
    exists = False
    crontab_path = "/var/spool/cron/crontabs/%s" % user
    lines = []
    if os.path.exists(crontab_path):
        exists = True
        with open(crontab_path) as fp:
            for line in fp.readlines():
                if line.startswith("#"):
                    logging.debug("commentline: %s", line)
                    continue
                elif not line.strip():
                    logging.debug("empty line: %s", line)
                    continue
                else:
                    logging.debug("valid line: %s", line)
                    lines.append(line)
    return exists, crontab_path, lines


def main(router, hosts, user):

    # list of hosts to operate on
    contexts = {host: router.ssh(hostname=host) for host in hosts}

    # have a map of context IDs => hostnames to recover from the
    # latter in async call results. cargo-culted from
    # https://github.com/dw/mitogen/blob/a60c6c14a2473c895162a1b58a81bad0e63d1718/examples/select_loop.py
    hostname_by_context_id = {
        context.context_id: hostname for hostname, context in contexts.items()
    }
    for msg in Select(c.call_async(hunt_crontab, user) for c in contexts.values()):
        host = hostname_by_context_id[msg.src_id]

        try:
            # Prints output once it is received.
            exists, path, lines = msg.unpickle()
            if exists:
                if lines:
                    logging.info(
                        "found crontab %s on %s, content: %r", path, host, lines
                    )
                else:
                    logging.info(
                        "crontab %s exists, but has no command defined on %s",
                        path,
                        host,
                    )
            else:
                logging.debug("crontab %s not found on %s", path, host)
        except mitogen.core.CallError as e:
            print("Call failed:", str(e))


if __name__ == "__main__":
    mitogen.utils.log_to_file()
    args = parse_args()
    logging.info("dispatching crontab search on hosts %s", " ".join(args.hosts))
    broker = mitogen.master.Broker()
    router = mitogen.master.Router(broker)
    with router:
        main(router, args.hosts, args.user)
