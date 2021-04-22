from green_cli.authenticators import *

class WatchOnlyAuthenticator:
    """Watch-only logins"""

    def __init__(self, options):
        config_dir = options['config_dir']
        self._username = ConfigProperty(config_dir, 'username', lambda: input('Username: '))
        self._password = ConfigProperty(config_dir, 'password', getpass)

    def set_username(self, username):
        self._username.set(username)

    def set_password(self, password):
        self._password.set(password)

    def login(self, session_obj):
        credentials = {'username': self._username.get(), 'password': self._password.get()}
        return gdk.login_user(session_obj, '{}', json.dumps(credentials))


def get_authenticator(options):
    return WatchOnlyAuthenticator(options)
