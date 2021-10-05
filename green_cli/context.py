import atexit
import sys

from green_cli import version
from green_cli.session import Session

class Context:
    """Holds global context related to the invocation of the tool"""

    def __init__(self):
        self._session = None
        self.authenticator = None
        self.options = None
        self.logged_in = False
        self.configured = False

    def configure(self, authenticator, options):
        self.authenticator = authenticator
        self.options = options
        self.__dict__.update(options)
        self.configured = True

    @property
    def session(self):
        if self._session is None:
            session_params = {
                'name': self.options['network'],
                'use_tor': self.options['tor'],
                'log_level': self.options['gdk_log'],
                'user_agent': 'green_cli_{}'.format(version),
            }

            optional_keys = ['cert_expiry_threshold']
            overrides = {k: v for (k, v) in self.options.items() if k in optional_keys and v is not None}
            session_params.update(overrides)

            self._session = Session(session_params)
            atexit.register(self._session.destroy)
        return self._session

sys.modules[__name__] = Context()
