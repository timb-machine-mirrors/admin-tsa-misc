# this file has global configuration for Fabric, as per:
#
# https://docs.fabfile.org/en/2.5/concepts/configuration.html

# we want to connect to remote servers as root
#
# XXX: this doesn't work if the user explicitely made a different
# config in ~/.ssh/config. that's up to the user to fix that problem,
# although we do explicitely specify a host in certain context where
# we know it's likely the user configured a non-root user for push
# (e.g. puppet.torproject.org).
user = 'root'
