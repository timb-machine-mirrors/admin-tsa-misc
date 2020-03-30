Commands here are designed to run under fabric. You can list the
available jobs with:

    fab --list

For example, tasks can be called individually with:

    fab -H unifolium.torproject.org --dry libvirt.instance-running test.torproject.org

Otherwise, some modules are also designed to be called directly, for
example:

    python3 -m fabric_tpa.retire --parent-host unifolium.torproject.org --dryrun test-01.torproject.org

WARNING: All the code here has only been tested summarily and should
be handled with extreme care. Use `--dry` to see what will happen
first.

See also the full documentation at <https://help.torproject.org/tsa/howto/fabric/>
