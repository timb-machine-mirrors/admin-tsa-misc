#!/usr/bin/python3

import warnings

# expose all modules to fabric
from invoke import Collection

import fabric
import fabric.connection

import fabric_tpa.retire
import fabric_tpa.ganeti
import fabric_tpa.host
import fabric_tpa.libvirt
import fabric_tpa.reboot

from fabric_tpa import SaferConnection

ns = Collection(
    fabric_tpa.retire,
    fabric_tpa.ganeti,
    fabric_tpa.host,
    fabric_tpa.libvirt,
    fabric_tpa.reboot,
)

# monkeypatch the default fabric connexion to workaround
# https://github.com/fabric/fabric/issues/2071
warnings.warn('Fabric Connection monkeypatched, will crash without a patch')
fabric.Connection = SaferConnection
fabric.connection.Connection = SaferConnection
