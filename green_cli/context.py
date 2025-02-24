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
                'user_agent': 'green_cli_{}'.format(version),
                'spv_enabled': self.options['spv'],
            }

            optional_keys = [
                'blob_server_url',
                'cert_expiry_threshold',
                'electrum_onion_url',
                'electrum_url',
                'electrum_tls',
            ]
            overrides = {k: v for (k, v) in self.options.items() if k in optional_keys and v is not None}
            session_params.update(overrides)

            self._session = Session(session_params)
        return self._session

    def color(self):
        return False if self.no_color else None  # None means let click decide

sys.modules[__name__] = Context()
