from green_cli.authenticators import *

class WatchOnlyAuthenticator:
    """Watch-only logins"""

    def __init__(self, config_dir):
        self._username = ConfigProperty(config_dir, 'username', lambda: input('Username: '))
        self._password = ConfigProperty(config_dir, 'password', getpass)

    def set_username(self, username):
        self._username.set(username)

    def set_password(self, password):
        self._password.set(password)

    def login(self, session_obj):
        return gdk.login_watch_only(session_obj, self._username.get(), self._password.get())


def get_authenticator(network, config_dir):
    return WatchOnlyAuthenticator(config_dir)
