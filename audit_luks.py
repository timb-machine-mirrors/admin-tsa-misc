#!/usr/bin/python3

"""Detect outdated cryptographic configuration on LUKS
partitions. Note that this program will *not* warn on plain text
partitions."""

import argparse
import json
import logging
import os
import shlex
import subprocess
from typing import Iterator


def audit_luks_disk(path: str) -> tuple[int, tuple[str, ...]]:
    command = ["cryptsetup", "luksDump", "--dump-json-metadata", path]
    logging.debug("running command %s", shlex.join(command))
    ret = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if ret.returncode != 0:
        logging.warning(ret.stderr.decode("utf-8").strip())
        if (
            b"--dump-json-metadata: unknown option" in ret.stderr
            or b"Dump operation is not supported for this device type." in ret.stderr
        ):
            logging.warning(
                "disk %s is using LUKS1, convert with `cryptsetup convert %s --type luks2",
                path,
                path,
            )
            return (1, ())
        else:
            ret.check_returncode()
    logging.info("device %s is using LUKS2", path)
    logging.debug("stdout: %r", ret.stdout)
    luks_header = json.loads(ret.stdout)
    logging.debug("JSON: %r", luks_header)
    # assert len(luks_header.get('keyslots', {})) > 1, "no keyslots??"
    types = []
    for i, keyslot in luks_header.get("keyslots", {}).items():
        KDF = str(keyslot.get("kdf", {}).get("type"))
        if KDF != "argon2id":
            logging.warning(
                "keyslot %d KDF: %s, convert with `cryptsetup luksConvertKey %s --pbkdf argon2id`",
                int(i),
                KDF,
                path,
            )
        else:
            logging.info("keyslot %d KDF: %s", int(i), KDF)
        types.append(KDF)
    return (2, tuple(types))


def find_crypt_devices() -> Iterator[str]:
    ret = subprocess.run(
        ["lsblk", "--json"],
        stdout=subprocess.PIPE,
        check=True,
    )
    devices = json.loads(ret.stdout)
    for device in devices.get("blockdevices", []):
        yield from find_crypt_device(device)


def find_crypt_device(device: dict) -> Iterator[str]:
    for children in device.get("children", []):
        if children["type"] == "crypt":
            yield device["name"]
        yield from find_crypt_device(children)


class LoggingAction(argparse.Action):
    """change log level on the fly

    The logging system should be initialized befure this, using
    `basicConfig`.
    """

    def __init__(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        """setup the action parameters

        This enforces a selection of logging levels. It also checks if
        const is provided, in which case we assume it's an argument
        like `--verbose` or `--debug` without an argument.
        """
        kwargs["choices"] = logging._nameToLevel.keys()
        if "const" in kwargs:
            kwargs["nargs"] = 0
        super().__init__(*args, **kwargs)

    def __call__(self, parser, ns, values, option):  # type: ignore[no-untyped-def]
        """if const was specified it means argument-less parameters"""
        if self.const:
            logging.getLogger("").setLevel(self.const)
        else:
            logging.getLogger("").setLevel(values)
        # cargo-culted from _StoreConstAction
        setattr(ns, self.dest, self.const or values)


def main():
    logging.basicConfig(format="%(levelname)s: %(message)s", level="INFO")
    parser = argparse.ArgumentParser(epilog=__doc__)
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
        "devices",
        help="devices to inspect, default to autodetect",
        nargs="*",
    )
    args = parser.parse_args()
    safe = True
    os.environ["LC_ALL"] = "C.UTF-8"  # to get consistent error messages
    for device in args.devices or find_crypt_devices():
        version, types = audit_luks_disk("/dev/%s" % device)
        if version == 1 or set(types) != {"argon2id"}:
            safe = False
    if safe:
        logging.info("all is well, no LUKS1 or non-argon2id encryption found")
    else:
        logging.warning("LUKS1 or non-argon2id encryption found")


if __name__ == "__main__":
    main()
