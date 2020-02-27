Commands here are designed to run under fabric. You can list the
available jobs with:

    fab --list

For example, commands in `host_decom` can be called individually with:

    fab -H unifolium.torproject.org --dry libvirt.instance-running test.torproject.org

Otherwise, some modules are also designed to be called directly, for
example:

    python3 -m fabric_tpa.decom --parent-host unifolium.torproject.org --dryrun test-01.torproject.org

WARNING: All the code here has only been tested summarily and should
be handled with extreme care. Use `--dry` to see what will happen
first.

References:

 * [automate installs][]
 * [automate reboots][]
 * [automate retirement][]
 * [Python LDAP][] could be used to automate talking with ud-ldap,
   see in particular the [Python LDAP functions][], in particular
   [add][] and [delete][]
 * The above docs are very limited, and they [suggest][] external
   resources also:
   * https://hub.packtpub.com/python-ldap-applications-extra-ldap-operations-and-ldap-url-library/
   * https://hub.packtpub.com/configuring-and-securing-python-ldap-applications-part-2/
   * https://www.linuxjournal.com/article/6988

[automate installs]: https://trac.torproject.org/projects/tor/ticket/31239
[automate reboots]: https://trac.torproject.org/projects/tor/ticket/33406
[automate retirement]: https://trac.torproject.org/projects/tor/ticket/33477
[Python LDAP]: https://www.python-ldap.org/
[Python LDAP functions]: https://www.python-ldap.org/en/python-ldap-3.2.0/reference/ldap.html#functions
[delete]: https://www.python-ldap.org/en/python-ldap-3.2.0/reference/ldap.html#ldap.LDAPObject.delete
[add]: https://www.python-ldap.org/en/python-ldap-3.2.0/reference/ldap.html#ldap.LDAPObject.add
[suggest]: https://www.python-ldap.org/en/python-ldap-3.2.0/resources.html
