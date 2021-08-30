#!/usr/bin/python3
# coding: utf-8

"""handle abuse reports from Hetzner"""
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

import argparse
from email.parser import BytesParser, Parser
from email.policy import default
import logging
import quopri
import sys


__epilog__ = """This will read a message specified on the commandline or stdin and
try to find a way to "opt out" the user that complained. This is
specifically designed to handle messages forwarded by the Hetzner
hosting services, but could be expanded for others."""


def parse_args(args=sys.argv[1:]):
    parser = argparse.ArgumentParser(description=__doc__, epilog=__epilog__)
    parser.add_argument("--dryrun", "-n", action="store_true", help="do nothing")
    parser.add_argument(
        "-q",
        "--quiet",
        action=LoggingAction,
        const="WARNING",
        help="silence messages except warnings and errors",
    )
    parser.add_argument(
        "-d",
        "--debug",
        action=LoggingAction,
        const="DEBUG",
        help="enable debugging messages",
    )
    parser.add_argument(
        "messages",
        nargs="*",
        help="message files to parse, use - for stdin, default: stdin",
    )
    return parser.parse_args(args=args)


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
        # cargo-culted from _StoreConstAction
        setattr(ns, self.dest, self.const or values)


REGEX_OPTOUT = r"https://donate[^/]*\.torproject\.org/civicrm/mailing/optout"


def process_file(stream):
    msg = BytesParser(policy=default).parse(stream)
    logging.debug("walking message %r", msg)
    for part in msg.walk():
        filename = part.get_filename()
        if filename is not None and filename.startswith("Abuse Message"):
            logging.debug(
                "parsing abuse message %s (%s)",
                filename,
                part.get_content_type(),
            )
            parse_abuse_message(part.get_content())
        else:
            logging.debug("skipping part %s", part.get_content_type())


def parse_abuse_message(content):
    msg_abuse = Parser(policy=default).parsestr(content)
    logging.debug("parsed message %r (%d bytes)", msg_abuse, len(str(msg_abuse)))
    for part_abuse in msg_abuse.walk():
        logging.debug("checking part %r (%d bytes)", part_abuse, len(str(part_abuse)))
        if part_abuse.get_content_type() == "text/rfc822-headers":
            logging.info("Found headers, dumping to stdout")
            process_abuse_message_headers(part_abuse.get_content())
        elif part_abuse.get_content_type() == "message/rfc822":
            # yes, the *entire* message is quoted-printable encoded
            process_abuse_message_rfc822(part_abuse.get_content())


def process_abuse_message_headers(content):
    # TODO: postfix-trace on crm?
    print(content)


def process_abuse_message_rfc822(content):
    msg_actual_bytes = quopri.decodestring(bytes(content))
    msg_actual = BytesParser(policy=default).parsebytes(msg_actual_bytes)

    logging.info(
        "Found email %r (%d bytes), grepping for pattern",
        msg_actual,
        len(msg_actual_bytes),
    )
    unsub = msg_actual.get("List-Unsubscribe")
    if unsub is not None:
        logging.info("found unsubscribe link: %s", unsub)
        # TODO: send an email? follow URL?
        print(unsub)
    else:
        logging.warning("no valid unsubscribe link in actual message: %s", msg_actual)


def main(args):
    files = args.messages
    if not files:
        files = ("-",)
    else:
        files = tuple(files)
    logging.info("processing messages in %s", files)
    for path in files:
        if path == "-":
            process_file(sys.stdin.buffer)  # read stdin as binary
        else:
            with open(path, "rb") as stream:
                process_file(stream)


if __name__ == "__main__":
    logging.basicConfig(format="%(message)s")  # INFO is default
    args = parse_args()
    main(args)
