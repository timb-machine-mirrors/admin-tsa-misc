Commands here are designed to run under fabric. You can list the
available jobs with:

    fab --list

For example, commands in `host_decom` can be called individually with:

    fab -H unifolium.torproject.org --dry host-decom.kvm-instance-running test.torproject.org

Otherwise, modules are also designed to be called directly, for
example:

    python3 -m fabric_tpa.host_decom --parent-host unifolium.torproject.org --dryrun test-01.torproject.org
