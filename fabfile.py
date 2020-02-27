#!/usr/bin/python3

# expose all modules to fabric
from invoke import Collection

import fabric_tpa.retire
import fabric_tpa.ganeti
import fabric_tpa.host
import fabric_tpa.kvm_migrate
import fabric_tpa.libvirt
import fabric_tpa.reboot

ns = Collection(
    fabric_tpa.retire,
    fabric_tpa.ganeti,
    fabric_tpa.host,
    fabric_tpa.kvm_migrate,
    fabric_tpa.libvirt,
    fabric_tpa.reboot,
)
