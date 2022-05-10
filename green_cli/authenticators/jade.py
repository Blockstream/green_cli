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
            is_segwit = input['address_type'] in ['p2wsh', 'csv', 'p2sh-p2wpkh', 'p2wpkh']
            mapped = { 'is_witness': is_segwit,
                       'path': input['user_path'],
                       'script': bytes.fromhex(input['prevout_script'])}

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

    # Helper to get the commitment and blinding key from Jade
    def _get_trusted_commitments(self, index: int, output: Dict, hash_prevouts: bytes, custom_vbf: bytes) -> Dict:
        commitments = self.jade.get_commitments(
            bytes.fromhex(output['asset_id']),
            output['satoshi'],
            hash_prevouts,
            index,
            custom_vbf)

        # Add the script blinding key and return
        commitments['blinding_key'] = bytes.fromhex(output['blinding_key'])
        return commitments

    # Poke the blinding factors and commitments into the results structure
    @staticmethod
    def _populate_result(trusted_commitments: Dict, result: Dict) -> Dict:
        asset_blinders, value_blinders, asset_generators, value_commitments = [], [], [], []
        for commitments in trusted_commitments:
            if commitments is None:
                # Unblinded/fee output - 'null' entries
                for lst in asset_blinders, value_blinders, asset_generators, value_commitments:
                    lst.append(None)
            else:
                asset_blinders.append(commitments['abf'][::-1].hex())
                value_blinders.append(commitments['vbf'][::-1].hex())
                asset_generators.append(commitments['asset_generator'].hex())
                value_commitments.append(commitments['value_commitment'].hex())

        result['assetblinders'] = asset_blinders
        result['amountblinders'] = value_blinders
        result['asset_commitments'] = asset_generators
        result['value_commitments'] = value_commitments
        return result

    def sign_tx(self, details: Dict) -> Dict:
        txhex = details['transaction']['transaction']
        signing_inputs = details['signing_inputs']
        use_ae_protocol = details['use_ae_protocol']
        transaction_outputs = details['transaction_outputs']
        logging.debug('sign liquid txn with %d inputs and %d outputs',
                      len(signing_inputs), len(transaction_outputs))

        def _map_input(input: Dict) -> Dict:
            is_segwit = input['address_type'] in ['p2wsh', 'csv', 'p2sh-p2wpkh', 'p2wpkh']
            mapped = { 'is_witness': is_segwit,
                       'path': input['user_path'],
                       'value_commitment': bytes.fromhex(input['commitment']),
                       'script': bytes.fromhex(input['prevout_script'])}

            # Additional fields to pass through if using the Anti-Exfil protocol
            if use_ae_protocol:
                mapped['ae_host_commitment'] = bytes.fromhex(input['ae_host_commitment'])
                mapped['ae_host_entropy'] = bytes.fromhex(input['ae_host_entropy'])

            return mapped

        # Get inputs and change outputs in form Jade expects
        jade_inputs = list(map(_map_input, signing_inputs))
        change = list(map(self._map_change_output, transaction_outputs))

        # Calculate the hash-prevout from the inputs
        values, abfs, vbfs, input_prevouts = [], [], [], []
        for input in signing_inputs:
            # Get values, abfs and vbfs from inputs (needed to compute the final output vbf)
            values.append(input['satoshi'])
            abfs.append(bytes.fromhex(input['assetblinder'])[::-1])
            vbfs.append(bytes.fromhex(input['amountblinder'])[::-1])

            # Get the input prevout txid and index for hashing later
            input_prevouts.append(bytes.fromhex(input['txhash'])[::-1])
            input_prevouts.append(input['pt_idx'].to_bytes(4, byteorder='little'))

        hash_prevouts = bytes(wally.sha256d(b''.join(input_prevouts)))

        # Get the trusted commitments from Jade
        idx, trusted_commitments = 0, []
        blinded_outputs = transaction_outputs[:-1]  # Assume last output is fee
        for output in blinded_outputs[:-1]:  # Not the last blinded output as we calculate the vbf for that
            commitments = self._get_trusted_commitments(idx, output, hash_prevouts, None)
            trusted_commitments.append(commitments)

            values.append(output['satoshi'])
            abfs.append(commitments['abf'])
            vbfs.append(commitments['vbf'])
            idx += 1

        # Calculate the final vbf
        values.append(blinded_outputs[idx]['satoshi'])
        finalAbf = self.jade.get_blinding_factor(hash_prevouts, idx, 'ASSET')
        abfs.append(finalAbf)
        final_vbf = bytes(wally.asset_final_vbf(values, len(signing_inputs), b''.join(abfs), b''.join(vbfs)))

        # Get the final trusted commitments from Jade (with the calculated vbf)
        commitments = self._get_trusted_commitments(idx, blinded_outputs[idx], hash_prevouts, final_vbf)
        trusted_commitments.append(commitments)

        # Add a 'null' commitment for the final (fee) output
        trusted_commitments.append(None)

        # Get the asset-registry entries for any assets in the tx outputs
        # NOTE: must contain sufficient data for jade to be able to verify (ie. contract, issuance)
        # Not passing 'refresh=True' here so will only use already downloaded/cached asset info
        all_assets = context.session.refresh_assets({'assets': True})['assets']
        tx_asset_ids = set(output['asset_id'] for output in transaction_outputs)
        tx_asset_info = [all_assets.get(asset_id) for asset_id in tx_asset_ids]
        tx_assets_sanitised = [asset for asset in tx_asset_info if asset and asset.get('contract') and asset.get('issuance_prevout')]

        # Sign!
        txn = bytes.fromhex(txhex)
        signatures = self.jade.sign_liquid_tx(self.network, txn, jade_inputs, trusted_commitments, change, use_ae_protocol, tx_assets_sanitised)
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

        # Poke the blinding factors into the results structure
        self._populate_result(trusted_commitments, result)

        logging.debug('resolving {}'.format(result))
        return json.dumps(result)


def get_authenticator(options: Dict):
    if 'liquid' in options['network']:
        return JadeAuthenticatorLiquid(options)
    else:
        return JadeAuthenticator(options)
