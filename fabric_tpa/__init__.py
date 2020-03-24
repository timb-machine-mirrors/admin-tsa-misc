import atexit
import datetime
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
    from fabric import Config, Connection
    from fabric.main import Fab, Executor
except ImportError:
    sys.stderr.write('cannot find fabric, install with `apt install python3-fabric`')  # noqa: E501
    raise

from paramiko.client import RejectPolicy
from invoke import Argument


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
