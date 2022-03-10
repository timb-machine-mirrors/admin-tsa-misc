# TPA miscellaneous scripts

A mostly random collection of sysadmin scripts we can't seem to fit
anywhere else.

## Project inventory

Here are the known objects here:

 * `fabric_tpa`: our growing pile of code built around Fabric,
   typically a library for other tools in the top level directory, but
   many functions can be called directly, see `fab -l` after
   installing fabric

 * `fabric.yml`, `fabfile.py`: config files for Fabric

 * `find-crontabs.py`: a prototype experimenting with mitogen as a
   Fabric replacement

 * `ganeti`: a bunch of tools for managing Ganeti clusters

 * `handle-abuse.py`: pipe an abuse message from Hetzner in there to
   unsubscribe users from CiviCRM (among, hopefully, other things)

 * `install`: fabric-based installer

 * `installer`: a lot of legacy installers, some of which are still in
   use

 * `multi-tool`: legacy, should be replaced by `cumin` or the `reboot`
   fabric script

 * `reboot`: a script to reboot or halt servers reliably, built with
   Fabric

 * `reboot-guest`, `reboot-host`: legacy reboot scripts

 * `retire`: a script to (partially) retire a server, built with
   Fabric

## Caveats

This README file should probably be expanded to cover a little more
about the history of this project, its authors, and possible fate(s).

In particular, we might want to move all the Fabric-related Python
code to its own repository, with CI and all that jazz.
