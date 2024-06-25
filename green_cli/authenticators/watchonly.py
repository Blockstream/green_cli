from green_cli.authenticators import *

class WatchOnlyAuthenticator:
    """Watch-only logins"""

    def __init__(self, options):
        config_dir = options['config_dir']
        self._username = ConfigProperty(config_dir, 'username', lambda: input('Username: '))
        self._password = ConfigProperty(config_dir, 'password', getpass)
        if options['blob_server_url']:
            self._watch_only_data = ConfigProperty(config_dir, 'watch_only_data', lambda: input('watch_only_data: '))

    @property
    def name(self):
        return 'watch-only signer'

    def set_username(self, username):
        self._username.set(username)

    def set_password(self, password):
        self._password.set(password)

    def set_watch_only_data(self, watch_only_data):
        self._watch_only_data.set(watch_only_data)

    def login(self, session_obj):
        credentials = {'username': self._username.get(), 'password': self._password.get()}
        if hasattr(self, '_watch_only_data'):
            watch_only_data = self._watch_only_data.get()
            if watch_only_data:
                credentials['watch_only_data'] = watch_only_data
        return gdk_resolve(gdk.login_user(session_obj, '{}', json.dumps(credentials)))


def get_authenticator(options):
    return WatchOnlyAuthenticator(options)
