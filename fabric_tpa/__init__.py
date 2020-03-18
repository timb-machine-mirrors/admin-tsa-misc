import logging
import sys

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
    def __init__(self, *args, **kwargs):
        super().__init__(*args,
                         executor_class=Executor,
                         config_class=Config,
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


class SaferConnection(Connection):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.client.set_missing_host_key_policy(RejectPolicy())
