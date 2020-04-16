#!/usr/bin/python3

# expose all modules to fabric
from invoke import Collection

# get the safe_open hack
import fabric_tpa  # noqa: F401
import fabric_tpa.ganeti
import fabric_tpa.host
import fabric_tpa.libvirt
import fabric_tpa.reboot
import fabric_tpa.retire
import fabric_tpa.user

ns = Collection(
    fabric_tpa.ganeti,
    fabric_tpa.host,
    fabric_tpa.libvirt,
    fabric_tpa.reboot,
    fabric_tpa.retire,
    fabric_tpa.user,
)
