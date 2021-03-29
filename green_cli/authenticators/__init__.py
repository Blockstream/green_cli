import base64
import json
import logging
import os
import stat

from typing import Dict, List
from getpass import getpass

import click

import greenaddress as gdk


class Authenticator:
    """Provide authentication"""

    # Provide init() function with expected signature so all subclasses can
    # safely call super().__init__(options)
    def __init__(self, options):
        super().__init__()

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


class MnemonicOnDisk:
    """Persist a mnemonic using the filesystem"""

    def __init__(self, options):
        super().__init__(options)

        # mnemonic file has read-only permissions to prevent accidental deletion
        prompt_fn = lambda: getpass('Mnemonic: ')
        config_dir = options['config_dir']
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


class SoftwareAuthenticator(MnemonicOnDisk, Authenticator):
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

    def create(self, session_obj, words):
        """Create and register a new wallet"""
        if words == 24:
            self._mnemonic = gdk.generate_mnemonic()
        elif words == 12:
            self._mnemonic = gdk.generate_mnemonic_12()
        else:
            raise click.ClickException("Unsupported number of words")

        assert len(self._mnemonic.split()) == words
        return self.register(session_obj)

    def set_mnemonic(self, mnemonic):
        mnemonic = ' '.join(mnemonic.split())
        logging.debug("mnemonic: '{}'".format(mnemonic))
        if not gdk.validate_mnemonic(mnemonic):
            raise click.ClickException("Invalid mnemonic")
        self._mnemonic = mnemonic


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
            result = json.dumps({'signature': signature.hex()})
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
