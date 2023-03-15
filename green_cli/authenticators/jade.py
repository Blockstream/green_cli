import wallycore as wally
import greenaddress as gdk

import base64
import json
import logging

from typing import List

from green_cli.authenticators import *
from green_cli import context

try:
    import jadepy
except ImportError as e:
    jadepy = None
    logging.debug('Failed to import jadepy: {}'.format(e))


class JadeAuthenticator(MnemonicOnDisk, HardwareDevice):

    """Uses Jade device to authenticate"""

    # Minimum supported fw version - liquid swaps and explicit blinding step
    MIN_SUPPORTED_VERSION = (0, 1, 48)

    @staticmethod
    def _get_descriptor(addr_type: str) -> str:
         return {'p2pkh': 'pkh(k)',
                 'p2sh-p2wpkh': 'sh(wpkh(k))',
                 'p2wpkh': 'wpkh(k)'}.get(addr_type)

    def __init__(self, options: Dict):
        self.info = None
        super().__init__(options)
        self.network = options['network']
        self.jade = None

        # Map 'electrum-<xxx>' networks to <xxx>
        if self.network.startswith('electrum-'):
            self.network = self.network[len('electrum-'):]

        # For debug jades/tests we can skip PIN auth by forcing the local mnemonic into the hww.
        # NOTE: this only works when using a DEBUG build of the Jade firmware.
        auth_config = options['auth_config']
        self.debug_push_mnemonic = auth_config.get('debug_push_mnemonic')

        # Default connection details
        config_dir = options['config_dir']
        self.ble_serial_number = ConfigProperty(config_dir, 'jadebleserialnumber', lambda: '')
        self.usb_serial_device = ConfigProperty(config_dir, 'jadeusbserialdevice', lambda: '')

        # Any specific connection details passed in explicit config
        self.connection_details = auth_config.get('connection_details', {})

    # By default prefer to use Anti-Exfil signatures
    # (sacrifices low-r guarantee)
    @property
    def default_hw_device_info(self):
        return {'device': {
                  'name': self.name,
                  'supports_low_r': False,
                  'supports_liquid': 0,
                  'supports_ae_protocol': 1,
                  'supports_arbitrary_scripts': True}
               }

    def set_usb_serial_device(self, usb_serial_device: str):
        self.usb_serial_device.set(usb_serial_device)

    def set_ble_serial_number(self, ble_serial_number: str):
        self.ble_serial_number.set(ble_serial_number)

    def _connect(self):
        if self.jade:
            # Already connected - no-op
            return

        if 'ble_serial_number' in self.connection_details:
            # Have explicit BLE connection details - connect via BLE
            self.jade = jadepy.JadeAPI.create_ble(serial_number=self.connection_details['ble_serial_number'])
        elif 'usb_serial_device' in self.connection_details:
            # Have explicit serial connection details - connect via serial
            self.jade = jadepy.JadeAPI.create_serial(device=self.connection_details['usb_serial_device'])
        elif self.ble_serial_number.get():
            # Have saved BLE connection details - connect via BLE
            self.jade = jadepy.JadeAPI.create_ble(serial_number=self.ble_serial_number.get())
        else:
            # If nothing else - connect via serial, using any saved config is present
            self.jade = jadepy.JadeAPI.create_serial(device=self.usb_serial_device.get())

        self.jade.connect()
        self.info = self.jade.get_version_info()
        logging.debug('Connected to {}: {}'.format(self.name, self.info))

        # Quick'n'dirty version check
        vers = self.info['JADE_VERSION'].split('.')[:3]
        vers[-1] = vers[-1].split('-')[0]  # truncate any suffix
        if tuple(map(int, vers)) < self.MIN_SUPPORTED_VERSION:
            raise click.ClickException(f"Unsupported Jade firmware version - {self.MIN_SUPPORTED_VERSION} required")

        entropy = gdk.get_random_bytes(wally.BIP39_ENTROPY_LEN_256)
        self.jade.add_entropy(entropy)

    # Debug only - push a mnemonic into jade device
    def _debug_push_mnemonic_into_jade(self):
        mnemonic = self.debug_push_mnemonic or self._mnemonic
        logging.warning('Pushing local mnemonic to jade (debug/testing): {}'.format(mnemonic))
        assert self.jade.set_mnemonic(mnemonic)

    # Proper authentication using the pinserver
    def _auth_user(self, session_obj):
        # Use gdk as http proxy
        def _gdk_http_request(params):
            logging.debug('Calling gdk http_request() with: {}'.format(params))
            reply = gdk.http_request(session_obj, json.dumps(params))
            logging.debug('Response from gdk http_request(): {}'.format(reply))
            return json.loads(reply)

        while not self.jade.auth_user(self.network, http_request_fn=_gdk_http_request):
            logging.warning('Jade authentication failed.')

    def _ensure_ready(self, session_obj):
        self._connect()

        if self.debug_push_mnemonic:
            self._debug_push_mnemonic_into_jade()
        else:
            self._auth_user(session_obj)

    @property
    def name(self):
        return 'Jade@{}'.format(self.info['EFUSEMAC'][6:]) if self.info else 'Jade'

    def login(self, session_obj):
        # Ensure jade is set-up/unlocked, and then log in.
        # (Unlocking is required here as login() will call get_xpub() and sign_msg(),
        # which require the Jade hw be authorised/unlocked.)
        self._ensure_ready(session_obj)
        return super().login(session_obj)

    def register(self, session_obj):
        """Register an existing wallet"""
        # Ensure jade is set-up/unlocked, and then register the wallet.
        # (Unlocking is required here as registering will call get_xpub(), which
        # requires the Jade hw be authorised/unlocked.)
        self._ensure_ready(session_obj)
        return super().register(session_obj)

    def get_xpub(self, path: List[int]) -> str:
        return self.jade.get_xpub(self.network, path)

    def sign_message(self, details: Dict) -> Dict:
        path = details['path']
        message = details['message']
        result = {}

        if details['use_ae_protocol']:
            ae_host_commitment =  bytes.fromhex(details['ae_host_commitment'])
            ae_host_entropy = bytes.fromhex(details['ae_host_entropy'])
            signer_commitment, sig_encoded = self.jade.sign_message(path, message, True,
                                                                    ae_host_commitment,
                                                                    ae_host_entropy)
            result['signer_commitment'] = signer_commitment.hex()
        else:
            sig_encoded = self.jade.sign_message(path, message)

        sig_decoded = base64.b64decode(sig_encoded)

        # Need to truncate lead byte if recoverable signature
        if len(sig_decoded) == wally.EC_SIGNATURE_RECOVERABLE_LEN:
            sig_decoded = sig_decoded[1:]

        der_sig = wally.ec_sig_to_der(sig_decoded)
        result['signature'] = der_sig.hex()
        return result

    @classmethod
    def _map_change_output(cls, output: Dict) -> Dict:
        if output['is_change']:
            change = { 'path': output['user_path'] }
            if output.get('recovery_xpub'):
                change['recovery_xpub'] = output.get('recovery_xpub')

            if output['address_type'] == 'csv':
                change['csv_blocks'] = output['subtype']
            else:
                variant = cls._get_descriptor(output['address_type'])
                if variant is not None:
                    change['variant'] = variant

            return change

    def sign_tx(self, details: Dict) -> Dict:
        txhex = details['transaction']['transaction']
        signing_transactions = details['signing_transactions']
        signing_inputs = details['signing_inputs']
        use_ae_protocol = details['use_ae_protocol']
        transaction_outputs = details['transaction_outputs']
        logging.debug('sign txn with %d inputs and %d outputs',
                      len(signing_inputs), len(transaction_outputs))

        def _map_input(input: Dict) -> Dict:
            if input.get('skip_signing', False):
                # Not signing this input (may not belong to this signer)
                logging.debug(f'Not signing input: skip_signing=True')
                return dict()

            is_segwit = input['address_type'] in ['p2wsh', 'csv', 'p2sh-p2wpkh', 'p2wpkh']
            mapped = { 'is_witness': is_segwit,
                       'path': input['user_path'],
                       'script': bytes.fromhex(input['prevout_script']),
                       'sighash': input.get('user_sighash', wally.WALLY_SIGHASH_ALL) }

            # Additional fields to pass through if using the Anti-Exfil protocol
            if use_ae_protocol:
                mapped['ae_host_commitment'] = bytes.fromhex(input['ae_host_commitment'])
                mapped['ae_host_entropy'] = bytes.fromhex(input['ae_host_entropy'])

            # Jade has an optimisation for txns with only a single segwit input
            # where we can skip passing in the entire prior tx and instead pass
            # just the utxo amount (in sats).  In all other cases we pass the
            # input tx so the hw can verify the utxo amount from the output.
            # NOTE: this is optional, and we should get the same signature if
            # passed in the full input txn.
            if is_segwit and len(signing_inputs) == 1:
                mapped['satoshi'] = input['satoshi']
            else:
                input_txhex = signing_transactions[input['txhash']]
                mapped['input_tx'] = bytes.fromhex(input_txhex)

            return mapped

        # Get inputs and change outputs in form Jade expects
        jade_inputs = list(map(_map_input, signing_inputs))
        change = list(map(self._map_change_output, transaction_outputs))

        # Sign!
        txn = bytes.fromhex(txhex)
        signatures = self.jade.sign_tx(self.network, txn, jade_inputs, change, use_ae_protocol)
        assert len(signatures) == len(signing_inputs)

        result = {}
        if use_ae_protocol:
            # If using the Anti-Exfil protocol, the response is a list of
            # (signer_commitment, signature), so need to unzip the lists
            signer_commitments, signatures = zip(*signatures)
            signer_commitments = list(map(bytes.hex, signer_commitments))
            result['signer_commitments'] = signer_commitments

        signatures = list(map(bytes.hex, signatures))
        result['signatures'] = signatures

        logging.debug('resolving {}'.format(result))
        return json.dumps(result)


class JadeAuthenticatorLiquid(JadeAuthenticator):

    # By default prefer to use Anti-Exfil signatures
    # (sacrifices low-r guarantee)
    @property
    def default_hw_device_info(self):
        return {'device': {
                  'name': self.name,
                  'supports_low_r': False,
                  'supports_liquid': 1,
                  'supports_ae_protocol': 1,
                  'supports_host_unblinding': True,
                  'supports_arbitrary_scripts': True}
               }

    @property
    def master_blinding_key(self) -> bytes:
        try:
            return self.jade.get_master_blinding_key()
        except jadepy.JadeError as e:
            if e.code == jadepy.JadeError.USER_CANCELLED:
                return bytes()  # user declining is ok, return empty data
            raise

    def get_public_blinding_key(self, script: bytes) -> bytes:
        return self.jade.get_blinding_key(script)

    def get_shared_nonce(self, pubkey: bytes, script: bytes) -> bytes:
       return self.jade.get_shared_nonce(script, pubkey)

    def get_blinding_factor(self, hash_prevouts: bytes, output_index: int) -> bytes:
       return self.jade.get_blinding_factor(hash_prevouts, output_index, 'ASSET_AND_VALUE')

    def sign_tx(self, details: Dict) -> Dict:
        txhex = details['transaction']['transaction']
        signing_inputs = details['signing_inputs']
        use_ae_protocol = details['use_ae_protocol']
        transaction_outputs = details['transaction_outputs']
        logging.debug('sign liquid txn with %d inputs and %d outputs',
                      len(signing_inputs), len(transaction_outputs))

        def _map_input(input: Dict) -> Dict:
            if input.get('skip_signing', False):
                # Not signing this input (may not belong to this signer)
                logging.debug(f'Not signing input: skip_signing=True')
                return dict()

            is_segwit = input['address_type'] in ['p2wsh', 'csv', 'p2sh-p2wpkh', 'p2wpkh']
            mapped = { 'is_witness': is_segwit,
                       'path': input['user_path'],
                       'value_commitment': bytes.fromhex(input['commitment']),
                       'script': bytes.fromhex(input['prevout_script']),
                       'sighash': input.get('user_sighash', wally.WALLY_SIGHASH_ALL) }

            # Additional fields to pass through if using the Anti-Exfil protocol
            if use_ae_protocol:
                mapped['ae_host_commitment'] = bytes.fromhex(input['ae_host_commitment'])
                mapped['ae_host_entropy'] = bytes.fromhex(input['ae_host_entropy'])

            return mapped

        # Get inputs and change outputs in form Jade expects
        jade_inputs = list(map(_map_input, signing_inputs))
        change = list(map(self._map_change_output, transaction_outputs))

        # Get the output blinding info
        def _map_commitments_info(output):
            if 'assetblinder' not in output or 'amountblinder' not in output:
                # Output not blinded (or not by us), return null placeholder
                return None

            # Return blinding data
            return {
                'asset_id': bytes.fromhex(output['asset_id']),
                'abf': bytes.fromhex(output['assetblinder'])[::-1],
                'value': output['satoshi'],
                'vbf': bytes.fromhex(output['amountblinder'])[::-1],
                'blinding_key': bytes.fromhex(output['blinding_key'])
            }

        # Get inputs and change outputs in form Jade expects
        commitments = list(map(_map_commitments_info, transaction_outputs))

        # Get the asset-registry entries for any assets in the tx outputs
        # NOTE: must contain sufficient data for jade to be able to verify (ie. contract, issuance)
        # Not calling 'refresh_assets' here so will only use already downloaded/cached asset info
        all_assets = context.session.get_assets({'category': 'all'})['assets']
        tx_asset_ids = set(output['asset_id'] for output in transaction_outputs)
        tx_asset_info = [all_assets.get(asset_id) for asset_id in tx_asset_ids]
        tx_assets_sanitised = [asset for asset in tx_asset_info if asset and asset.get('contract') and asset.get('issuance_prevout')]

        # Sign!
        txn = bytes.fromhex(txhex)
        signatures = self.jade.sign_liquid_tx(self.network, txn, jade_inputs, commitments, change, use_ae_protocol, tx_assets_sanitised)
        assert len(signatures) == len(signing_inputs)

        result = {}
        if use_ae_protocol:
            # If using the Anti-Exfil protocol, the response is a list of
            # (signer_commitment, signature), so need to unzip the lists
            signer_commitments, signatures = zip(*signatures)
            signer_commitments = list(map(bytes.hex, signer_commitments))
            result['signer_commitments'] = signer_commitments

        signatures = list(map(bytes.hex, signatures))
        result['signatures'] = signatures

        logging.debug('resolving {}'.format(result))
        return json.dumps(result)


def get_authenticator(options: Dict):
    if 'liquid' in options['network']:
        return JadeAuthenticatorLiquid(options)
    else:
        return JadeAuthenticator(options)
