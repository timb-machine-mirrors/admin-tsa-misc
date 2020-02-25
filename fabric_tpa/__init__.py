#!/usr/bin/python3

# expose all modules to fab
from invoke import Collection

from . import ganeti
from . import host_decom
from . import kvm_migrate
from . import reboot

ns = Collection(ganeti, host_decom, kvm_migrate, reboot)
