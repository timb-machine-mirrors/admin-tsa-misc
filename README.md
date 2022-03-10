A mostly random collection of sysadmin scripts we can't seem to fit
anywhere else.

This is where our custom installer and batch jobs live. Here's the
known objects here:

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

This README deserves a better life.
