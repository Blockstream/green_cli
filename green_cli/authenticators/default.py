from green_cli.authenticators import *

class DefaultAuthenticator(SoftwareAuthenticator):
    """Adds pin login functionality"""

    def __init__(self, options):
        super().__init__(options)
        config_dir = options['config_dir']
        self.pin_data_filename = os.path.join(config_dir, 'pin_data')

    def login(self, session_obj):
        """Perform login with either mnemonic or pin data from local storage"""
        try:
            pin_data = open(self.pin_data_filename).read()
            pin = getpass("PIN: ")
            credentials = {'pin': pin, 'pin_data': json.loads(pin_data)}
            return gdk.login_user(session_obj, '{}', json.dumps(credentials))
        except (IOError, FileNotFoundError):
            pass
        return super().login(session_obj)

    def setpin(self, session, pin, device_id):
        credentials = session.get_credentials({}).resolve()
        assert credentials['mnemonic'] == self.mnemonic
        details = {'pin': pin, 'device_id': device_id, 'plaintext': credentials}
        pin_data = json.dumps(session.encrypt_with_pin(details).resolve()['pin_data'])
        open(self.pin_data_filename, 'w').write(pin_data)
        os.remove(self.mnemonic_prop.filename)
        return pin_data


def get_authenticator(options):
    return DefaultAuthenticator(options)
