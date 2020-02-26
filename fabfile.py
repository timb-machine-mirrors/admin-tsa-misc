#!/usr/bin/python3

# expose all modules to fabric
from invoke import Collection

import fabric_tpa.ganeti
import fabric_tpa.kvm_migrate
import fabric_tpa.host_decom
import fabric_tpa.reboot

ns = Collection(fabric_tpa.reboot,
                fabric_tpa.kvm_migrate,
                fabric_tpa.host_decom,
                fabric_tpa.ganeti)
