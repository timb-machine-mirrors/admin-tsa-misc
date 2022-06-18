#!/usr/bin/python3
# coding: utf-8

"""handle abuse reports from Hetzner"""

# Similar tools:
# https://github.com/LGUG2Z/unsubscan

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
from datetime import datetime, timezone
from email.errors import MessageParseError, MessageDefect
from email.message import EmailMessage
from email.parser import BytesParser, Parser
import email.policy
import logging
import quopri
import re
import shlex
from subprocess import Popen, PIPE
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


class Mailer:
    def sendmail(self):
        raise NotImplementedError()


class MailerSendmail(Mailer):
    def __init__(self, command="/usr/sbin/sendmail -t"):
        self.command = command

    def send(self, msg):
        """send an email using a local UNIX MTA

        There are at least 2 other ways of doing this: SMTP and using a
        MUA, both of which are (not really cleanly) implemented in
        Monkeysign here:

        https://0xacab.org/monkeysphere/monkeysign/-/blob/e0cf4269674ad0a8df7d52451caaed3ab97ba397/monkeysign/ui.py#L689

        For now, we keep this simple.
        """
        try:
            # we shlex so that the "command" can (eventually?) be
            # supplied by the user
            p = Popen(shlex.split(self.command), stdin=PIPE, stdout=PIPE, stderr=PIPE)
        except OSError as e:
            logging.warning("cannot find MTA %s: %s" % (self.command, repr(e)))
            return
        tosend = msg.as_string().encode("utf-8")
        logging.debug(
            "sending %d bytes message with command %s", len(tosend), self.command
        )
        stdout, stderr = p.communicate(tosend)
        if p.returncode == 0:
            logging.info("message sent to %s", msg["To"])
        else:
            logging.error(
                "failed to send message to %s with command %s: %s",
                msg["To"],
                self.command,
                stdout + stderr,
            )
        return p.returncode == 0


class MessageParser:
    """a parser to handle forwarded abuse messages

    This should read a forwarded message and try to extract
    information from it and store some state (in the `parse()`
    function), then unsubscribe the user based on that state (in the
    `unsubscribe()` function.

    This is an abstract class, subclasses implement the meat.

    This could be split in two classes: a parser that would yield an
    action, for example.
    """

    def parse(self, message):
        raise NotImplementedError()

    def unsubscribe(self):
        raise NotImplementedError()


class MessageParserRFC822(MessageParser):
    """parse a complete RFC822 message

    This is sent by some providers, in this case we just look for the
    `List-Unsubscribe` address and handle it correctly. For now it
    just supports mailto: link, but it could also do a GET on a HTTPS
    URL, if we ever hit those.
    """

    mailer = MailerSendmail()

    def __init__(self):
        self.msg = self.message_template()

    def parse(self, content):
        """decode the provided string"""
        # yes, the *entire* message is quoted-printable encoded
        content_bytes = quopri.decodestring(bytes(content))
        msg_actual = BytesParser(policy=email.policy.SMTP).parsebytes(
            bytes(content_bytes)
        )

        logging.info(
            "Found email %r (%d bytes), grepping for pattern",
            msg_actual,
            len(content_bytes),
        )
        unsub = msg_actual.get("List-Unsubscribe")
        if unsub is not None:
            logging.info("found unsubscribe link: %s", unsub)
            m = re.match(r"<mailto:([^>]*)>", unsub)
            if m:
                # this looks like a mailto link
                self.msg["To"] = m.group(1)
            else:
                raise RuntimeError(
                    "unsupported unsubscribe link in message: %s" % msg_actual
                )
            raise RuntimeError(
                "no List-Unsubscribe header in message: %s %r"
                % (msg_actual.get("Message-ID"), dict(msg_actual))
            )

    def message_template(cls):
        msg = EmailMessage()
        msg.set_content(
            """
        Please unsubscribe the user associated with this bounce address.

        Generated on %s by %s, source code in:

        %s
        """
            % (
                datetime.now(timezone.utc),
                sys.argv[0],
                "https://git.torproject.org/admin/tsa-misc",
            )
        )
        msg["Subject"] = "automated unsubscribe from TPA hande-abuse.py"
        return msg

    def unsubscribe(self):
        assert self.msg, "should have failed earlier"
        if self.msg["To"]:
            return self.mailer.send(self.msg)
        logging.warning("No 'To' header defined in mailer")
        return False

    def __str__(self):
        return self.msg.get("To", "<>")

    def __repr__(self):
        return "<%s(%s): %d bytes>" % (type(self).__name__, str(self), len(self.msg))


class HeadersParser(MessageParser):
    """this parses a text/rfc822-headers message

    Those are sent, for example, by AbuseFBLUnitedInternet (mail.com)
    and they look something like this:

    ----==_mimepart_612979b54399d_1e8f2ac0bda0596c78860
    Content-Type: text/plain;
     charset=UTF-8
    Content-Transfer-Encoding: 7bit
    Content-Disposition: attachment;
     filename="Abuse Message 91526923.txt"
    filename: Abuse Message 91526923.txt
    Content-ID: <[REDACTED]>

    Return-Path: <>
    Received: from mout-bounce.gmx.com ([74.208.4.220]) by mail.hetzner.company with esmtps (TLSv1.2:DHE-RSA-AES256-GCM-SHA384:256) (Exim 4.92) id 1mJlZ0-0005j4-2I for abuse@hetzner.com; Sat, 28 Aug 2021 01:47:33 +0200
    Received: from [10.241.66.4] ([10.241.66.4]) by unused (msvc-msubmit-portal006.server.lan [10.78.20.5]) (via HTTP); Sat, 28 Aug 2021 01:47:00 +0200
    Date: Fri, 27 Aug 2021 23:47:00 +0000
    From: noreply@fbl.mail.com
    To: abuse@hetzner.com
    Message-ID: <trinity-sys-NET-1f8984bd-63c9-494b-978c-9bcd57e775c5-1630108020453@msvc-msubmit-portal006>
    Subject: Abuse report for unknown domain
    Mime-Version: 1.0
    Content-Type: multipart/report;
     boundary="----=_Part_165831113_1285530079.1630108020452";
     report-type=report
    Content-Transfer-Encoding: 7bit
    Envelope-to: abuse@hetzner.com
    Delivery-date: Sat, 28 Aug 2021 01:47:33 +0200
    DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/simple; d=mail.com; s=isystem1;
     [REDACTED]
    X-UI-Sender-Class: adecfcb8-f391-4a10-92ea-8596fbbc6511
    Auto-Submitted: auto-generated
    X-UI-Out-Filterresults: notjunk:1;V03:K0:ZdI/io4Zyq0=:ShFTfz7Z+aeYbYEXzsef55
     LlYHrxVPBLd0tfWbj1f5QcWWeOqglASE52qEiLZLiW
    X-DKIM-Status: pass [(mail.com) - 74.208.4.220]
    X-Virus-Scanned: Clear (ClamAV 0.102.4/26276/Fri Aug 27 10:25:17 2021)
    X-Spam-Level: -1.4 (-)
    Delivered-To: vmail-abuse@hetzner.com


    ------=_Part_165831113_1285530079.1630108020452
    Content-Type: multipart/alternative;
     boundary="----=_Part_165831112_1973770691.1630108020452"
    Content-Transfer-Encoding: 7bit


    ------=_Part_165831112_1973770691.1630108020452
    Content-Type: text/plain;
     charset=UTF-8
    Content-Transfer-Encoding: 7bit

    This is an email abuse report for an email message from civicrm+b.3108.9688537.bab50b8c2fd5ffa1@crm.torproject.org on Fri, 27 Aug 2021 04:08:25 GMT
    ------=_Part_165831112_1973770691.1630108020452--

    ------=_Part_165831113_1285530079.1630108020452
    Content-Type: message/feedback-report;
     charset=UTF-8
    Content-Transfer-Encoding: 7bit

    Feedback-Type: abuse
    User-Agent: UI-PORTAL-FBL/0.1
    Version: 0.1
    Original-Mail-From: civicrm+b.3108.9688537.bab50b8c2fd5ffa1@crm.torproject.org
    Arrival-Date: Fri, 27 Aug 2021 04:08:25 GMT
    Source-Ip: 116.202.120.186
    ------=_Part_165831113_1285530079.1630108020452
    Content-Type: text/rfc822-headers;
     charset=UTF-8
    Content-Transfer-Encoding: 7bit

    Message-ID: <20210827033204.E147F10410F@crm-int-01.torproject.org>
    ------=_Part_165831113_1285530079.1630108020452--

    ----==_mimepart_612979b54399d_1e8f2ac0bda0596c78860--
    """  # noqa: E501

    def parse(self, content):
        m = re.match(r"Message-ID: <([^>]*)>", content)
        if m:
            self.message_id = m.group(1)
        else:
            raise RuntimeError(
                "No valid Message-ID found in provided headers: %s" % content
            )

    def unsubscribe(self):
        # TODO actually run this with fabric?
        command = "ssh crm-int-01.torproject.org postfix-trace %s" % self.message_id
        raise NotImplementedError(
            "finding actual email address not supported yet, run this SSH command: %s"
            % command
        )


class MessageParserFeedbackReport(MessageParserRFC822):
    """Parse a message/feedback-report message.

    This is part of the HeadersParser sample code above, and actually
    has the unsubscribe link. So if we're lucky, this works without
    having to do a trace on our message ID.

    This otherwise behaves like MessageParserRFC822 and will fire an
    email on `unsubscribe` to disable this user.

    Example MIME part:

    ------=_Part_165831113_1285530079.1630108020452
    Content-Type: message/feedback-report;
     charset=UTF-8
    Content-Transfer-Encoding: 7bit

    Feedback-Type: abuse
    User-Agent: UI-PORTAL-FBL/0.1
    Version: 0.1
    Original-Mail-From: civicrm+b.3108.9688537.bab50b8c2fd5ffa1@crm.torproject.org
    Arrival-Date: Fri, 27 Aug 2021 04:08:25 GMT
    Source-Ip: 116.202.120.186

    """

    ORIGINAL_MAIL_FROM_REGEX = r"^Original-Mail-From:\s+(civicrm\+[ub]\.[^@]*@crm\.torproject\.org)$"  # noqa: E501

    def parse(self, content):
        # try to handle quoted-printable Content-Transfer-Encoding,
        # may be related to: https://bugs.python.org/issue45066
        if re.search(rb"=$", content, re.MULTILINE):
            # this looks like quoted-printable, try to decode
            logging.debug(
                "found what looks like quoted printable message/feedback-report"
            )
            content = quopri.decodestring(content).decode("utf8")
        else:
            # not sure what encoding that header is supposed to be into,
            # but typically it's just ascii anyways
            logging.debug("assuming plain ASCII message/feedback-report")
            content = content.decode("ascii")
        m = re.search(
            self.ORIGINAL_MAIL_FROM_REGEX,
            content,
            re.MULTILINE,
        )
        if m:
            self.msg["To"] = m.group(1)
            logging.debug("found Original-Mail-From: %s", m.group(1))
        else:
            raise RuntimeError(
                "no Original-Mail-From header in feedback report: %s" % content
            )


def process_files(paths):
    success = False
    for path in paths:
        if path == "-":
            logging.info("processing standard input")
            stream = sys.stdin.buffer  # read stdin as binary
        else:
            logging.info("processing file %s", path)
            stream = open(path, "rb")
        for user in process_file(stream):
            if args.dryrun:
                logging.info("would have unsubscribed %s", user)
                success = True
                break
            else:
                if user.unsubscribe():
                    success = True
                    logging.info("unsubscribed user, finished processing %s", path)
                    break
        else:
            logging.warning("could not find a way to unsubscribe user in %s", path)
        if path != "-":
            stream.close()
    return success


class RawMessageParser(MessageParserRFC822):
    LIST_UNSUBSCRIBE_REGEX = r"^List-Unsubscribe: <mailto:(civicrm\+[bu]\.[^@]*@[^>]*)>$"  # noqa: E501

    def parse(self, content):
        m = re.search(
            self.LIST_UNSUBSCRIBE_REGEX,
            content,
            re.MULTILINE | re.DOTALL,
        )
        if m:
            mailto = m.group(1)
            if "=" in mailto:
                # probably quoted-printable encoded
                mailto = quopri.decodestring(mailto).decode("utf8")
            self.msg["To"] = mailto
            logging.debug("found List-Unsubscribe: %s", mailto)
        else:
            # try to find a message ID
            mid_matches = re.findall(r"^Message-ID:\s+<?([^>]+)>?$", content, re.MULTILINE)
            raise RuntimeError(
                "no known List-Unsubscribe header in raw message, Message-ID: %s" % mid_matches
            )


def process_file(stream):
    msg = BytesParser(policy=email.policy.default + email.policy.strict).parse(stream)
    logging.debug(
        "walking Message-ID %s (%d bytes)", msg.get("Message-ID"), len(str(msg))
    )
    for part in msg.walk():
        filename = part.get_filename()
        if filename is not None and filename.startswith("Abuse Message"):
            logging.debug(
                "parsing abuse message %s (%s)",
                filename,
                part.get_content_type(),
            )
            for method in parse_abuse_message(part.get_content()):
                yield method
        else:
            logging.debug("skipping part %s", part.get_content_type())


def parse_abuse_message(content):
    try:
        msg_abuse = Parser(policy=email.policy.default + email.policy.strict).parsestr(
            content
        )
    except (MessageParseError, MessageDefect) as e:
        # https://bugs.python.org/issue45066, triggered by Message-ID:
        # 60fd666f351f1_42382af4351a9970740a2@abuse.hetzner.company.mail
        logging.error("error parsing attached abuse message: %r", e)
        # falling back to brute force
        parser = RawMessageParser()
        logging.debug("trying parser %s", parser)
        try:
            parser.parse(content)
            yield parser
        except RuntimeError as e:
            logging.warning(str(e))
        return
    logging.debug(
        "parsed Message-ID %s (%d bytes)",
        msg_abuse.get("Message-ID"),
        len(str(msg_abuse)),
    )
    for part_abuse in msg_abuse.walk():
        content_type = part_abuse.get_content_type()
        logging.debug(
            "checking part %s (%d bytes)",
            content_type,
            len(str(part_abuse)),
        )
        parser = None
        if content_type.startswith("multipart"):
            content = None
        else:
            content = part_abuse.get_content()

        if content_type == "text/rfc822-headers":
            parser = HeadersParser()
        elif content_type == "message/feedback-report":
            parser = MessageParserFeedbackReport()
        elif content_type == "message/rfc822":
            parser = MessageParserRFC822()

        if parser:
            logging.debug("trying parser %r", parser)
            try:
                parser.parse(content)
                yield parser
            except RuntimeError as e:
                logging.warning(str(e))


def main(args):
    files = args.messages
    if not files:
        files = ("-",)
    else:
        files = tuple(files)
    logging.debug("processing messages in %s", files)
    if process_files(files):
        return 0
    else:
        return 1


if __name__ == "__main__":
    logging.basicConfig(format="%(message)s", level="INFO")
    args = parse_args()
    sys.exit(main(args))
