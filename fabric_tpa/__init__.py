import atexit
import datetime
import getpass
import hashlib

import logging
import os.path
import psutil
import sys

try:
    from humanize import naturalsize
except ImportError:
    sys.stderr.write('cannot import humanize, sizes will be ugly')

    def naturalsize(size, *args, **kwargs):
        return size + 'B'

try:
    import ldap
except ImportError:
    sys.stderr.write(
        "cannot find Python LDAP, install with `apt install python3-ldap`\n"
    )
    raise

try:
    from fabric import Config, Connection
    from fabric.main import Fab, Executor
except ImportError:
    sys.stderr.write('cannot find fabric, install with `apt install python3-fabric`')  # noqa: E501
    raise

from paramiko.client import RejectPolicy
from invoke import Argument


# some gymnastics to reimplement the nice extra features hexlify has
# in python 3.8, but unfortunately missing in earlier versions
from binascii import hexlify as stdlib_hexlify
if sys.version_info >= (3, 8):
    hexlify = stdlib_hexlify
else:
    def hexlify(data, sep, bytes_per_sep=1):
        """
        replacement for python 3.8's hexlify, which now nicely takes a separator

        data and sep are bytes, and it returns bytes

        this is typically used to decode a checksum into a human-readable form

        >>> hexlify_py38(b'0000', b':', 2)
        >>> b'30:30:30:30'
        """
        # turn bytes into hex
        s = stdlib_hexlify(data)
        # take the bytes and split them with the separator:
        # 1. take a byte and the next N: s[i:i+bytes_per_sep]
        # 2. for each byte, skipping N: range(0, len(s), bytes_per_sep)
        # 3. rejoin by on the separator: sep.join
        return sep.join(s[i:i+bytes_per_sep] for i in range(0, len(s), bytes_per_sep))


class VerboseProgram(Fab):
    # cargo-culted from fab's main.py
    def __init__(self, *args,
                 executor_class=Executor,
                 config_class=Config,
                 **kwargs):
        super().__init__(*args,
                         executor_class=executor_class,
                         config_class=config_class,
                         **kwargs)

    def core_args(self):
        core_args = super().core_args()
        extra_args = [
            Argument(
                names=('verbose', 'v'),
                kind=bool,
                default=False,
                help="be more verbose"
            ),
        ]
        return core_args + extra_args

    def parse_core(self, argv):
        # override basic format
        logging.basicConfig(format='%(message)s')
        super().parse_core(argv)
        if self.args.debug.value:
            logging.getLogger('').setLevel(logging.DEBUG)
        elif self.args.verbose.value:
            logging.getLogger('').setLevel(logging.INFO)
        # override default logging policies in submodules
        #
        # without this, we get debugging info from paramiko with --verbose
        for mod in 'fabric', 'paramiko', 'invoke':
            logging.getLogger(mod).setLevel('WARNING')
        self._tpa_timer = Timer()
        logging.info('starting tasks at %s', self._tpa_timer.stamp)
        atexit.register(self._tpa_log_completion)

    def _tpa_log_completion(self):
        logging.info('completed tasks, %s', self._tpa_timer)


Connection.default_host_key_policy = RejectPolicy


# hack to fix Fabric key policy:
# https://github.com/fabric/fabric/issues/2071
def safe_open(self):
    SaferConnection.setup_ssh_client(self)
    Connection.open_orig(self)


class SaferConnection(Connection):
    # this function is a copy-paste from
    # https://github.com/fabric/fabric/pull/2072
    def setup_ssh_client(self):
        if self.default_host_key_policy is not None:
            logging.debug('host key policy: %s', self.default_host_key_policy)
            self.client.set_missing_host_key_policy(self.default_host_key_policy())
        known_hosts = self.ssh_config.get('UserKnownHostsFile'.lower(),
                                          '~/.ssh/known_hosts')
        logging.debug('loading host keys from %s', known_hosts)
        # multiple keys, seperated by whitespace, can be provided
        for filename in [os.path.expanduser(f) for f in known_hosts.split()]:
            if os.path.exists(filename):
                self.client.load_host_keys(filename)


Connection.open_orig = Connection.open
Connection.open = safe_open


class Timer(object):
    """this class is to track time and resources passed

    originally from bup-cron, but improved to include memory usage"""

    def __init__(self):
        """initialize the timstamp"""
        self.stamp = datetime.datetime.now()

    def times(self):
        """return a string designing resource usage"""
        return 'user %s system %s chlduser %s chldsystem %s' % os.times()[:4]

    def rss(self):
        process = psutil.Process(os.getpid())
        return process.memory_info().rss

    def memory(self):
        return 'RSS %s' % naturalsize(self.rss())

    def diff(self):
        """a datediff between the creation of the object and now"""
        return datetime.datetime.now() - self.stamp

    def __str__(self):
        """return a string representing the time passed and resources used"""
        return 'elasped: %s (%s %s)' % (str(self.diff()),
                                        self.times(),
                                        self.memory())


def hash_digest_hex(data, hash=hashlib.md5, sep=':'):
    return hexlify(hash(data).digest(), sep, 2)


class LdapContext(object):
    """The LdapContext is a more pythonic wrapper around the python-ldap module

    It is very opinionated: it will setup TLS with a hardcoded
    certificate, for example, and hardcodes a binding domain. It will
    also prompt for a passphrase and does a search on SUBTREE.

    The point is to remove much of the LDAP intricacies from the
    caller so they don't have to know as much of the complexity of the
    protocol to do simple things. Obviously, the abstraction is leaky
    as we don't hide stuff like the filtering language or DNs.
    """

    # the default URI if not specified
    default_uri = "ldaps://db.torproject.org"
    # the base domain name for this domain, used in authentication and
    # search
    base_dn = "dc=torproject,dc=org"
    base_dn_users = "ou=users," + base_dn
    base_dn_hosts = "ou=hosts," + base_dn
    # how to construct a guessed username if not provided. the %s is
    # interpolated by bind() with getuser()
    base_dn_user_template = "uid=%s," + base_dn_users
    # the certificate to use to verify with the LDAP server
    tls_cacertfile = os.path.dirname(__file__) + "/db.torproject.org.pem"

    def __init__(self, uri=None):
        """initialize the LdapContext

        This initializes an `ldap` object from the given URI, which
        SHOULD have a ldaps:// prefix.

        It will also setup TLS using a hardcoded certificate and
        enforce it.

        """
        if uri is None:
            uri = self.default_uri
        self.uri = uri
        self.ldap = ldap.initialize(uri)
        # TODO: certificate might expire, check for expiry and renew
        # if necessary
        self.ldap.set_option(
            ldap.OPT_X_TLS_CACERTFILE,
            self.tls_cacertfile,
        )
        # default, but just making sure
        self.ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_HARD)

    def bind(self, dn=None, password=None):
        """bind to the initialized LDAP connection using the provided DN and
        password

        If the dn is None (default), it is guessed based on the
        current local user.

        If the `password` is None (default), it is prompted using the
        `getpass` library.

        This also sets the `dn` member value for debugging purposes.
        """
        if dn is None:
            dn = self.base_dn_user_template % getpass.getuser()
        self.dn = dn
        if password is None:
            password = getpass.getpass(
                prompt="%s LDAP password for %s: " % (self.uri, dn)
            )
        self.ldap.simple_bind_s(dn, password)

    def search(self, filterstr='(objectClass=*)', base=None):
        """Search the given base for the filterstr"""
        if base is None:
            base = self.base_dn
        logging.debug('searching for %r inside %r', filterstr, base)
        return self.ldap.search_s(
            base=base, filterstr=filterstr, scope=ldap.SCOPE_SUBTREE,
        )

    def search_users(self, filterstr='(objectClass=*)', base=None):
        """Search for users matching the filter string (filterstr)

        This is a wrapper around search but with the default `base`
        set to the the preconfigured base_dn_users,
        e.g. ou=users,dc=example,dc=com.
        """
        if base is None:
            base = self.base_dn_users
        return self.search(filterstr=filterstr, base=base)

    def search_hosts(self, filterstr='(objectClass=*)', base=None):
        """Search for hosts matching the filter string (filterstr)

        This is a wrapper around search but with the default `base`
        set to the the preconfigured base_dn_hosts,
        e.g. ou=hosts,dc=example,dc=com.
        """
        if base is None:
            base = self.base_dn_hosts
        return self.search(filterstr=filterstr, base=base)

    def __str__(self):
        """string representation of this object

        This censors the password, which is not kept, for security reasons."""
        return "LdapContext(%r, %r, %r): %s" % (
            self.uri,
            self.dn,
            "[CENSORED]",
            self.ldap,
        )
