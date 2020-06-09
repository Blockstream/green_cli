import base64
import json
import logging
import os
import stat

from typing import Dict, List
from getpass import getpass

import hwilib.commands
import click

import greenaddress as gdk


try:
    import wallycore as wally
except ImportError as e:
    wally = None
    logging.warning("Failed to import wallycore: %s", e)


class Authenticator:
    """Provide authentication"""

    def login(self, session_obj):
        return gdk.login(session_obj, self.hw_device, self.mnemonic, self.password)

    def register(self, session):
        return gdk.register_user(session, self.hw_device, self.mnemonic)


class ConfigProperty:
    """A piece of data that is stored in a file in the config directory"""

    def __init__(self, config_dir, filename, prompt_fn, file_perms=stat.S_IRUSR | stat.S_IWUSR):
        self.filename = os.path.join(config_dir, filename)
        self.prompt_fn = prompt_fn
        self.file_perms = file_perms

    def get(self):
        """Read the value from the config file, or failing that prompt the user"""
        try:
            return open(self.filename).read()
        except IOError:
            value = self.prompt_fn()
            self.set(value)
            return value

    def set(self, value):
        open(self.filename, 'w').write(value)
        os.chmod(self.filename, self.file_perms)


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


class MnemonicOnDisk:
    """Persist a mnemonic using the filesystem"""

    def __init__(self, config_dir):
        # mnemonic file has read-only permissions to prevent accidental deletion
        prompt_fn = lambda: getpass('Mnemonic: ')
        self.mnemonic_prop = ConfigProperty(config_dir, 'mnemonic', prompt_fn, stat.S_IRUSR)

    @property
    def _mnemonic(self):
        return self.mnemonic_prop.get()

    @_mnemonic.setter
    def _mnemonic(self, mnemonic):
        """Write mnemonic to config file"""
        try:
            self.mnemonic_prop.set(mnemonic)
        except PermissionError:
            message = (
                "Refusing to overwrite mnemonic file {}\n"
                "First backup and then delete or change file permissions"
                .format(self.mnemonic_prop.filename))
            raise click.ClickException(message)


class SoftwareAuthenticator(Authenticator, MnemonicOnDisk):
    """Represent a 'software signer' which passes the mnemonic to the gdk for authentication
    """

    @property
    def hw_device(self):
        return json.dumps({})

    @property
    def mnemonic(self):
        return self._mnemonic

    @property
    def password(self):
        return ''

    def create(self, session_obj):
        """Create and register a new wallet"""
        self._mnemonic = gdk.generate_mnemonic()
        return self.register(session_obj)

    def set_mnemonic(self, mnemonic):
        mnemonic = ' '.join(mnemonic.split())
        logging.debug("mnemonic: '{}'".format(mnemonic))
        if not gdk.validate_mnemonic(mnemonic):
            raise click.ClickException("Invalid mnemonic")
        self._mnemonic = mnemonic


class DefaultAuthenticator(SoftwareAuthenticator):
    """Adds pin login functionality"""

    def __init__(self, config_dir):
        super().__init__(config_dir)
        self.pin_data_filename = os.path.join(config_dir, 'pin_data')

    def login(self, session_obj):
        """Perform login with either mnemonic or pin data from local storage"""
        try:
            pin_data = open(self.pin_data_filename).read()
            pin = input("PIN: ")
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


class HardwareDevice(Authenticator):
    """Represents what the gdk refers to as a 'hardware device'.

    Not necessarily an actual hardware device, but anything that implements the required hardware
    device interface
    """

    @property
    def hw_device(self):
        return json.dumps({'device': {'name': self.name, 'supports_liquid': 1,
            'supports_low_r': True, 'supports_arbitrary_scripts': True}})

    @property
    def mnemonic(self):
        return ''

    @property
    def password(self):
        return ''

    def resolve(self, details):
        """Resolve a requested action using the device"""
        logging.debug("%s resolving %s", self.name, details)
        details = details['required_data']
        if details['action'] == 'get_xpubs':
            xpubs = []
            paths = details['paths']
            logging.debug('get_xpubs paths = %s', paths)
            for path in paths:
                xpub = self.get_xpub(path)
                logging.debug('xpub for path %s: %s', path, xpub)
                xpubs.append(xpub)
            response = json.dumps({'xpubs': xpubs})
            logging.debug('resolving: %s', response)
            return response
        if details['action'] == 'sign_message':
            logging.debug('sign message path = %s', details['path'])
            message = details['message']
            logging.debug('signing message "%s"', message)
            signature = self.sign_message(details['path'], message)
            signature_hex = wally.hex_from_bytes(signature)
            result = json.dumps({'signature': signature_hex})
            logging.debug('resolving %s', result)
            return result
        if details['action'] == 'sign_tx':
            return self.sign_tx(details)
        if details['action'] == 'get_receive_address':
            blinding_script_hash = bytes.fromhex(details['address']['blinding_script_hash'])
            public_blinding_key = self.get_public_blinding_key(blinding_script_hash)
            return json.dumps({'blinding_key': public_blinding_key.hex()})

        retval = {}
        if details['action'] == 'create_transaction':
            blinding_keys = {}
            change_addresses = details['transaction'].get('change_address', {})
            for asset, addr in change_addresses.items():
                blinding_script_hash = bytes.fromhex(addr['blinding_script_hash'])
                blinding_keys[asset] = self.get_public_blinding_key(blinding_script_hash).hex()
            retval['blinding_keys'] = blinding_keys
        if 'blinded_scripts' in details:
            nonces = []
            for elem in details['blinded_scripts']:
                pubkey = bytes.fromhex(elem['pubkey'])
                script = bytes.fromhex(elem['script'])
                nonces.append(self.get_shared_nonce(pubkey, script).hex())
            retval['nonces'] = nonces

        if not retval:
            raise NotImplementedError("action = \"{}\"".format(details['action']))

        return json.dumps(retval)


class WallyAuthenticator(MnemonicOnDisk, HardwareDevice):
    """Stores mnemonic on disk but does not pass it to the gdk

    This class illustrates how the hardware device interface to the gdk can be used to implement all
    required crypto operations external to the gdk and thus avoid passing any key material to the
    gdk at all.
    """

    @property
    def name(self):
        return 'libwally software signer'

    def create(self, session_obj):
        """Create and register a new wallet"""
        logging.warning("Generating mnemonic using gdk")
        self._mnemonic = gdk.generate_mnemonic()
        return self.register(session_obj)

    @property
    def seed(self):
        _, seed = wally.bip39_mnemonic_to_seed512(self._mnemonic, None)
        return seed

    @property
    def master_key(self):
        return wally.bip32_key_from_seed(self.seed, wally.BIP32_VER_TEST_PRIVATE,
                                         wally.BIP32_FLAG_KEY_PRIVATE)

    def derive_key(self, path: List[int]):
        if not path:
            return self.master_key
        else:
            return wally.bip32_key_from_parent_path(self.master_key, path,
                                                    wally.BIP32_FLAG_KEY_PRIVATE)

    def get_xpub(self, path: List[int]):
        return wally.bip32_key_to_base58(self.derive_key(path), wally.BIP32_FLAG_KEY_PUBLIC)

    def get_privkey(self, path: List[int]) -> bytearray:
        return wally.bip32_key_get_priv_key(self.derive_key(path))

    def sign_message(self, path: List[int], message: str) -> bytearray:
        message = message.encode('utf-8')
        formatted = wally.format_bitcoin_message(message, wally.BITCOIN_MESSAGE_FLAG_HASH)
        privkey = self.get_privkey(path)
        signature = wally.ec_sig_from_bytes(privkey, formatted,
                                            wally.EC_FLAG_ECDSA | wally.EC_FLAG_GRIND_R)
        return wally.ec_sig_to_der(signature)

    def _get_sighash(self, wally_tx, index, utxo):
        flags = wally.WALLY_TX_FLAG_USE_WITNESS
        prevout_script = wally.hex_to_bytes(utxo['prevout_script'])
        return wally.tx_get_btc_signature_hash(
                wally_tx, index, prevout_script, utxo['satoshi'], wally.WALLY_SIGHASH_ALL, flags)

    def _sign_tx(self, details, wally_tx):
        txdetails = details['transaction']
        utxos = txdetails['used_utxos'] or txdetails['old_used_utxos']

        signatures = []
        for index, utxo in enumerate(utxos):

            is_segwit = utxo['script_type'] in [14, 15, 159, 162] # FIXME!!
            if not is_segwit:
                # FIXME
                raise NotImplementedError("Non-segwit input")

            txhash = self._get_sighash(wally_tx, index, utxo)

            path = utxo['user_path']
            privkey = self.get_privkey(path)
            signature = wally.ec_sig_from_bytes(privkey, txhash,
                                                wally.EC_FLAG_ECDSA | wally.EC_FLAG_GRIND_R)
            signature = wally.ec_sig_to_der(signature)
            signature.append(wally.WALLY_SIGHASH_ALL)
            signatures.append(wally.hex_from_bytes(signature))
            logging.debug('Signature (der) input %s path %s: %s', index, path, signature)

        return {'signatures': signatures}

    def sign_tx(self, details):
        tx_flags = wally.WALLY_TX_FLAG_USE_WITNESS
        wally_tx = wally.tx_from_hex(details['transaction']['transaction'], tx_flags)
        return json.dumps(self._sign_tx(details, wally_tx))

class HWIDevice(HardwareDevice):

    @staticmethod
    def _path_to_string(path: List[int]) -> str:
        """Return string representation of path for hwi interface

        The gdk passes paths as lists of int, hwi expects strings with '/'s
        >>> _path_to_string([1, 2, 3])
        "m/1/2/3"
        """
        return '/'.join(['m'] + [str(path_elem) for path_elem in path])

    def __init__(self, details: Dict):
        """Create a hardware wallet instance

        details: Details of hardware wallet as returned by hwi enumerate command
        """
        self.details = details
        self._device = hwilib.commands.find_device(details['path'])

    @property
    def name(self) -> str:
        """Return a name for the device, e.g. 'ledger@0001:0007:00'"""
        return '{}@{}'.format(self.details['type'], self.details['path'])

    def get_xpub(self, path: List[int]) -> bytes:
        """Return a base58 encoded xpub

        path: Bip32 path of xpub to return
        """
        path = HWIDevice._path_to_string(path)
        return hwilib.commands.getxpub(self._device, path)['xpub']

    def sign_message(self, path: List[int], message: str) -> bytes:
        """Return der encoded signature of a message

        path: BIP32 path of key to use for signing
        message: Message to be signed
        """
        path = HWIDevice._path_to_string(path)

        click.echo('Signing with hardware device {}'.format(self.name))
        click.echo('Please check the device for interaction')

        signature = hwilib.commands.signmessage(self._device, message, path)['signature']
        return wally.ec_sig_to_der(base64.b64decode(signature)[1:])

    def sign_tx(self, details):
        raise NotImplementedError("hwi sign tx not implemented")

    @staticmethod
    def get_device():
        """Enumerate and select a hardware wallet"""
        devices = hwilib.commands.enumerate()
        logging.debug('hwi devices: %s', devices)

        if len(devices) == 0:
            raise click.ClickException(
                "No hwi devices\n"
                "Check:\n"
                "- A device is attached\n"
                "- udev rules, device drivers, etc.\n"
                "- Cables/connections\n"
                "- The device is enabled, for example by entering a PIN\n")
        if len(devices) > 1:
            raise NotImplementedError("Device selection not implemented")

        device = devices[0]
        logging.debug('hwi device: %s', device)
        if 'error' in device:
            raise click.ClickException(
                "Error with hwi device: {}\n"
                "Check the device and activate the bitcoin app if necessary"
                .format(device['error']))
        return HWIDevice(device)
