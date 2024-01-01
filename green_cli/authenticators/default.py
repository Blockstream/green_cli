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
            with open(self.pin_data_filename) as f:
                pin_data = json.loads(f.read())

            for i in range(3):
                pin = getpass("PIN: ")
                credentials = json.dumps({'pin': pin, 'pin_data': pin_data})
                try:
                    return gdk_resolve(gdk.login_user(session_obj, '{}', credentials))
                except Exception as e:
                    if 'id_invalid_pin' in str(e):
                        click.echo('Invalid PIN, please try again')
                        continue
                    raise  # Some other error such as connection failed

            click.echo('Invalid PIN, no attempts remaining')
            # PIN is now invalid, remove pin_data and any saved PIN to
            # avoid re-prompting
            os.remove(self.pin_data_filename)
            os.remove(self.mnemonic_prop.filename)
            # Fall through to attempt mnemonic login below
        except (IOError, FileNotFoundError):
            # No PIN data found, login with mnemonic below
            pass
        return super().login(session_obj)

    def setpin(self, session, pin, device_id):
        credentials = session.get_credentials({}).resolve()
        assert credentials['mnemonic'] == self.mnemonic
        details = {'pin': pin, 'device_id': device_id, 'plaintext': credentials}
        pin_data = json.dumps(session.encrypt_with_pin(details).resolve()['pin_data'])
        with open(self.pin_data_filename, 'w') as f:
            f.write(pin_data)
        os.remove(self.mnemonic_prop.filename)
        return pin_data


def get_authenticator(options):
    return DefaultAuthenticator(options)
