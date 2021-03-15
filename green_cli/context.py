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

    def configure(self, authenticator, options):
        self.authenticator = authenticator
        self.options = options
        self.__dict__.update(options)

    @property
    def session(self):
        if self._session is None:
            session_params = {
                'name': self.options['network'],
                'use_tor': self.options['tor'],
                'log_level': self.options['gdk_log'],
                'user_agent': 'green_cli_{}'.format(version),
            }

            self._session = Session(session_params)
            atexit.register(self._session.destroy)
        return self._session

sys.modules[__name__] = Context()
