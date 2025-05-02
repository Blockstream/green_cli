import base64
import json
import logging
import os
import stat

from typing import Dict, List, Optional
from getpass import getpass

import click

import wallycore as libwally
import green_gdk as gdk
from green_cli.gdk_resolve import gdk_resolve


class Authenticator:
    """Provide authentication"""

    # Provide init() function with expected signature so all subclasses can
    # safely call super().__init__(options)
    def __init__(self, options):
        super().__init__()
        self.default_net_params = gdk.get_networks()[options['network']]

    def get_credentials(self):
        if self.hw_device == '{}':
            credentials = {'mnemonic': self.mnemonic, 'password': self.password}
        else:
            credentials = {}  # Hardware login, do not pass credentials
        return json.dumps(credentials)

    def login(self, session_obj):
        return gdk_resolve(gdk.login_user(session_obj, self.hw_device, self.get_credentials()))

    def register(self, session_obj):
        return gdk.register_user(session_obj, self.hw_device, self.get_credentials())


class ConfigProperty:
    """A piece of data that is stored in a file in the config directory"""

    def __init__(self, config_dir, filename, prompt_fn, file_perms=stat.S_IRUSR | stat.S_IWUSR):
        self.filename = os.path.join(config_dir, filename)
        self.prompt_fn = prompt_fn
        self.file_perms = file_perms

    def get(self):
        """Read the value from the config file, or failing that prompt the user"""
        try:
            with open(self.filename) as f:
                return f.read()
        except IOError:
            value = self.prompt_fn()
            self.set(value)
            return value

    def set(self, value):
        with open(self.filename, 'w') as f:
            f.write(value)
        os.chmod(self.filename, self.file_perms)


class MnemonicOnDisk:
    """Persist a mnemonic using the filesystem"""

    def __init__(self, options):
        super().__init__(options)

        # mnemonic file has read-only permissions to prevent accidental deletion
        prompt_fn = lambda: getpass('Mnemonic: ')
        config_dir = options['config_dir']
        self.mnemonic_prop = ConfigProperty(config_dir, 'mnemonic', prompt_fn, stat.S_IRUSR)

    @staticmethod
    def normalize_mnemonic(mnemonic):
        return ' '.join(mnemonic.split())

    @property
    def _mnemonic(self):
        return MnemonicOnDisk.normalize_mnemonic(self.mnemonic_prop.get())

    @_mnemonic.setter
    def _mnemonic(self, mnemonic):
        """Write mnemonic to config file"""
        try:
            self.mnemonic_prop.set(MnemonicOnDisk.normalize_mnemonic(mnemonic))
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
        if len(self._mnemonic.split()) == 27:
            return getpass('Mnemonic password: ')
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
        mnemonic = MnemonicOnDisk.normalize_mnemonic(mnemonic)
        words = mnemonic.split()
        is_encrypted = len(words) == 27
        logging.debug("mnemonic: '{}'".format(mnemonic))
        # For now no validation of encrypted mnemonic
        if not is_encrypted:
            if not gdk.validate_mnemonic(mnemonic):
                raise click.ClickException("Invalid mnemonic")
        self._mnemonic = mnemonic


class HardwareDevice(Authenticator):
    """Represents what the gdk refers to as a 'hardware device'.

    Not necessarily an actual hardware device, but anything that implements the required hardware
    device interface
    """

    def __init__(self, options):
        super().__init__(options)
        self.hw_device_data = self.default_hw_device_info
        device_overrides = options['auth_config'].get('device', dict())
        self.hw_device_data['device'].update(device_overrides)

    @property
    def default_hw_device_info(self):
        return {
            'device': {
                'name': self.name,
                'supports_low_r': False,
                'supports_liquid': 0,
                'supports_host_unblinding': False,
                'supports_external_blinding': False,
                'supports_arbitrary_scripts': True
            }
        }

    @property
    def hw_device(self):
        return json.dumps(self.hw_device_data)

    @property
    def mnemonic(self):
        return ''

    @property
    def password(self):
        return ''

    def get_blinding_factors(self, details: Dict) -> Dict:
        h2b_rev = lambda h: bytes.fromhex(h)[::-1]
        b2h_rev = lambda b: b[::-1].hex()

        # Compute hashPrevouts to derive deterministic blinding factors from
        txhashes = b''.join([h2b_rev(u['txhash']) for u in details['transaction_inputs']])
        output_indices = [u['pt_idx'] for u in details['transaction_inputs']]
        hash_prevouts = bytes(libwally.get_hash_prevouts(txhashes, output_indices))
        is_partial = details.get('is_partial', False)
        abfs, vbfs = [], []

        # Enumerate the outputs and provide blinding factors as needed
        final_i = len(details['transaction_outputs']) - 1
        for i, output in enumerate(details['transaction_outputs']):
            need_bfs = 'blinding_key' in output
            if need_bfs:
                # Call derived hww implementation to get abf+vbf
                abf_vbf = self.get_blinding_factor(hash_prevouts, i)

            abfs.append(b2h_rev(abf_vbf[:32]) if need_bfs else '')

            # Skip final vbf for non-partial txs; it is calculated by gdk
            need_bfs = need_bfs and (is_partial or i != final_i)
            vbfs.append(b2h_rev(abf_vbf[32:]) if need_bfs else '')

        return json.dumps({'assetblinders': abfs, 'amountblinders': vbfs})

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
            logging.debug('signing message "%s"', details['message'])
            response = json.dumps(self.sign_message(details))
            logging.debug('resolving: %s', response)
            return response
        if details['action'] == 'get_blinding_factors':
            return self.get_blinding_factors(details)
        if details['action'] == 'sign_tx':
            return self.sign_tx(details)
        if details['action'] == 'get_master_blinding_key':
            return json.dumps({'master_blinding_key': self.master_blinding_key.hex()})
        if details['action'] == 'get_blinding_public_keys':
            public_keys = []
            for script in details['scripts']:
                # Note that a 'real' implementation should verify 'script'
                public_keys.append(self.get_public_blinding_key(bytes.fromhex(script)).hex())
            return json.dumps({'public_keys': public_keys})
        if details['action'] == 'get_blinding_nonces':
            keys_required = details.get("blinding_keys_required", False)
            public_keys, nonces = [], []
            for (pubkey, script) in zip(details['public_keys'], details['scripts']):
                if keys_required:
                    public_keys.append(self.get_public_blinding_key(bytes.fromhex(script)).hex())
                nonces.append(self.get_shared_nonce(bytes.fromhex(pubkey), bytes.fromhex(script)).hex())
            ret = {'nonces': nonces, 'public_keys': public_keys} if keys_required else {'nonces': nonces}
            return json.dumps(ret)

        raise NotImplementedError("action = \"{}\"".format(details['action']))
