from green_cli.authenticators import *

class DefaultAuthenticator(SoftwareAuthenticator):
    """Adds pin login functionality"""

    def __init__(self, config_dir):
        super().__init__(config_dir)
        self.pin_data_filename = os.path.join(config_dir, 'pin_data')

    def login(self, session_obj):
        """Perform login with either mnemonic or pin data from local storage"""
        try:
            pin_data = open(self.pin_data_filename).read()
            pin = getpass("PIN: ")
            return gdk.login_with_pin(session_obj, pin, pin_data)
        except IOError:
            return super().login(session_obj)

    def setpin(self, session, pin, device_id):
        # session.set_pin converts the pin_data string into a dict, which is not what we want, so
        # use the underlying call instead
        pin_data = gdk.set_pin(session.session_obj, self.mnemonic, pin, device_id)
        open(self.pin_data_filename, 'w').write(pin_data)
        os.remove(self.mnemonic_prop.filename)
        return pin_data


def get_authenticator(network, config_dir):
    return DefaultAuthenticator(config_dir)
