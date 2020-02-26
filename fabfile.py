#!/usr/bin/python3

# expose all modules to fabric
from invoke import Collection

import fabric_tpa.decom
import fabric_tpa.ganeti
import fabric_tpa.host
import fabric_tpa.kvm_migrate
import fabric_tpa.libvirt
import fabric_tpa.reboot

ns = Collection(
    fabric_tpa.decom,
    fabric_tpa.ganeti,
    fabric_tpa.host,
    fabric_tpa.kvm_migrate,
    fabric_tpa.libvirt,
    fabric_tpa.reboot,
)
