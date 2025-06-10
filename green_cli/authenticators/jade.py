import wallycore as wally
import green_gdk as gdk

import base64
import json
import logging
from collections import defaultdict
from typing import List

from green_cli.authenticators import *
from green_cli import context
from green_cli import tx

try:
    import jadepy
except ImportError as e:
    jadepy = None
    logging.debug('Failed to import jadepy: {}'.format(e))


class JadeAuthenticator(MnemonicOnDisk, HardwareDevice):

    """Uses Jade device to authenticate"""

    # Minimum supported fw version - liquid swaps and explicit blinding step
    # FIXME: TAPROOT: update to FW with p2tr support
    MIN_SUPPORTED_VERSION = (0, 1, 48)

    @staticmethod
    def _get_descriptor(addr_type: str) -> str:
        return {
            'p2pkh': 'pkh(k)',
            'p2sh-p2wpkh': 'sh(wpkh(k))',
            'p2wpkh': 'wpkh(k)',
            'p2tr': 'tr(k)'
        }.get(addr_type)

    @staticmethod
    def _get_tx_type(tx_type: tx.TxType) -> str:
        return {tx.TxType.SEND_PAYMENT: 'send_payment',
                tx.TxType.SWAP: 'swap',
                tx.TxType.UNKNOWN: 'unknown'}.get(tx_type)

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
        return {
            'device': {
                'name': self.name,
                'supports_ae_protocol': 1,
                'supports_arbitrary_scripts': True,
                'supports_liquid': 0,
                'supports_low_r': False,
                'supports_p2tr': True
            }
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
            ae_host_commitment = bytes.fromhex(details['ae_host_commitment'])
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

        result['signature'] = wally.ec_sig_to_der(sig_decoded).hex()
        return result

    @classmethod
    def _map_wallet_outputs(cls, output: Dict) -> Dict:
        wallet_output = None
        if 'user_path' in output:
            wallet_output = {'is_change': output.get('is_change', False),
                             'path': output['user_path']}

            if output.get('recovery_xpub'):
                wallet_output['recovery_xpub'] = output.get('recovery_xpub')

            if output['address_type'] == 'csv':
                wallet_output['csv_blocks'] = output['subtype']
            else:
                variant = cls._get_descriptor(output['address_type'])
                if variant is not None:
                    wallet_output['variant'] = variant

        return wallet_output

    def sign_tx(self, details: Dict) -> Dict:
        txhex = details['transaction']
        signing_transactions = details['signing_transactions']
        transaction_inputs = details['transaction_inputs']
        use_ae_protocol = details['use_ae_protocol']
        transaction_outputs = details['transaction_outputs']
        logging.debug('sign txn with %d inputs and %d outputs',
                      len(transaction_inputs), len(transaction_outputs))

        # Does this tx represent a simple send payment, a swap, etc
        txtype = tx.get_tx_type(details)
        logging.info("tx appears to be a " + str(txtype))
        if txtype != tx.TxType.SEND_PAYMENT:
            raise click.ClickException("Jade only supports simple send-payment BTC tx at this time")

        def _map_input(input: Dict) -> Dict:
            if input.get('skip_signing', False):
                # Not signing this input (may not belong to this signer)
                logging.debug(f'Not signing input: skip_signing=True')
                return dict()

            is_segwit = input['address_type'] in ['p2wsh', 'csv', 'p2sh-p2wpkh', 'p2wpkh', 'p2tr']
            is_p2tr = input['address_type'] == 'p2tr'
            if is_p2tr and not use_ae_protocol:
                raise click.ClickException("Taproot inputs can only be signed with Anti-Exfil enabled")

            def_sighash = wally.WALLY_SIGHASH_DEFAULT if is_p2tr else wally.WALLY_SIGHASH_ALL
            mapped = {
                'is_witness': is_segwit,
                'path': input['user_path'],
                'script': bytes.fromhex(input['prevout_script']),
                'sighash': input.get('user_sighash', def_sighash)
            }

            # Additional fields to pass through if using the Anti-Exfil protocol
            for k in ['ae_host_commitment', 'ae_host_entropy'] if use_ae_protocol else []:
                mapped[k] = bytes.fromhex(input.get(k, ''))

            input_txhex = signing_transactions[input['txhash']]
            mapped['input_tx'] = bytes.fromhex(input_txhex)
            return mapped

        # Get inputs and change outputs in form Jade expects
        jade_inputs = list(map(_map_input, transaction_inputs))
        wallet_outputs = list(map(self._map_wallet_outputs, transaction_outputs))

        # Sign!
        txn = bytes.fromhex(txhex)
        signatures = self.jade.sign_tx(self.network, txn, jade_inputs, wallet_outputs, use_ae_protocol)
        assert len(signatures) == len(transaction_inputs)

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
        return {
            'device': {
                'name': self.name,
                'supports_low_r': False,
                'supports_liquid': 1,
                'supports_host_unblinding': True,
                'supports_external_blinding': True,
                'supports_arbitrary_scripts': True,
                'supports_ae_protocol': 1,
                'supports_liquid_p2tr': True,
            }
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
        txhex = details['transaction']
        tx_flags = wally.WALLY_TX_FLAG_USE_WITNESS | wally.WALLY_TX_FLAG_USE_ELEMENTS
        wally_tx = wally.tx_from_hex(txhex, tx_flags)
        transaction_inputs = details['transaction_inputs']
        use_ae_protocol = details['use_ae_protocol']
        is_partial = details['is_partial']
        transaction_outputs = details['transaction_outputs']
        logging.debug('sign liquid txn with %d inputs and %d outputs',
                      len(transaction_inputs), len(transaction_outputs))

        # Does this tx represent a simple send payment, a swap, etc
        txtype = tx.get_tx_type(details)
        logging.info("tx appears to be a " + str(txtype))
        if txtype == tx.TxType.UNKNOWN:
            raise click.ClickException("Unrecognised transaction type")

        signing_input_amounts = defaultdict(lambda: 0)

        def _map_input(input: Dict) -> Dict:
            mapped = {}
            if 'scriptpubkey' in input:
                # Include the scriptpubkey if it was provided (for example
                # if this is a non-wallet input but a taproot signature is
                # required).
                # We need this for Liquid since we don't pass the UTXO txs.
                mapped['scriptpubkey'] = bytes.fromhex(input['scriptpubkey'])
            if 'asset_tag' in input:
                # As per the scriptpubkey above, add the asset if provided.
                mapped['asset_generator'] = bytes.fromhex(input['asset_tag'])

            if input.get('skip_signing', False):
                # Not signing this input (may not belong to this signer)
                logging.debug(f'Not signing input: skip_signing=True')
                return mapped

            # Collate wallet inputs totals, per asset
            signing_input_amounts[input.get('asset_id')] += input['satoshi']

            is_segwit = input['address_type'] in ['p2wsh', 'csv', 'p2sh-p2wpkh', 'p2wpkh', 'p2tr']
            is_p2tr = input['address_type'] == 'p2tr'
            if is_p2tr and not use_ae_protocol:
                raise click.ClickException("Taproot inputs can only be signed with Anti-Exfil enabled")

            def_sighash = wally.WALLY_SIGHASH_DEFAULT if is_p2tr else wally.WALLY_SIGHASH_ALL
            mapped.update({
                'is_witness': is_segwit,
                'path': input['user_path'],
                'value_commitment': bytes.fromhex(input['commitment']),
                'script': bytes.fromhex(input['prevout_script']),
                'sighash': input.get('user_sighash', def_sighash)
            })

            # If non-trivial tx, also send any blinding information per input
            if txtype != tx.TxType.SEND_PAYMENT and input.get('is_blinded'):
                mapped['asset_id'] = bytes.fromhex(input['asset_id'])

                if 'assetblinder' in input:
                    mapped['abf'] = bytes.fromhex(input['assetblinder'])[::-1]
                if 'asset_blind_proof' in input:
                    mapped['asset_blind_proof'] = bytes.fromhex(input['asset_blind_proof'])

                if 'amountblinder' in input:
                    mapped['vbf'] = bytes.fromhex(input['amountblinder'])[::-1]
                if 'value_blind_proof' in input:
                    mapped['value_blind_proof'] = bytes.fromhex(input['value_blind_proof'])

                mapped['value'] = input['satoshi']
                # value_commitment sent in any case

            # Additional fields to pass through if using the Anti-Exfil protocol
            for k in ['ae_host_commitment', 'ae_host_entropy'] if use_ae_protocol else []:
                mapped[k] = bytes.fromhex(input.get(k, ''))

            return mapped

        # Get inputs and wallet outputs in form Jade expects
        jade_inputs = list(map(_map_input, transaction_inputs))
        wallet_outputs = list(map(self._map_wallet_outputs, transaction_outputs))

        # Get the output blinding info
        wallet_output_amounts = defaultdict(lambda: 0)

        def _map_commitments_info(wally_tx, i, output):
            # Collate wallet output totals, per asset
            # NOTE: 'is_change' outputs are reversed from the inputs amount, so these
            #       totals represent net movements in and out of the wallet
            if 'user_path' in output:
                if output.get('is_change', False):
                    signing_input_amounts[output['asset_id']] -= output['satoshi']
                else:
                    wallet_output_amounts[output['asset_id']] += output['satoshi']

            if 'blinding_key' not in output:
                # Output not blinded, return null placeholder
                return None

            # Return blinding data
            mapped = {
                'asset_id': bytes.fromhex(output['asset_id']),
                'value': output['satoshi'],
                'blinding_key': bytes.fromhex(output['blinding_key'])
            }

            if 'assetblinder' in output:
                mapped['abf'] = bytes.fromhex(output['assetblinder'])[::-1]
            if 'asset_blind_proof' in output:
                mapped['asset_blind_proof'] = bytes.fromhex(output['asset_blind_proof'])

            if 'amountblinder' in output:
                mapped['vbf'] = bytes.fromhex(output['amountblinder'])[::-1]
            if 'value_blind_proof' in output:
                mapped['value_blind_proof'] = bytes.fromhex(output['value_blind_proof'])

            # Value and asset commitments are taken from the transaction
            mapped['value_commitment'] = wally.tx_get_output_value(wally_tx, i)
            mapped['asset_generator'] = wally.tx_get_output_asset(wally_tx, i)
            return mapped

        # Get inputs and change outputs in form Jade expects
        commitments = []
        for i, output in enumerate(transaction_outputs):
            commitments.append(_map_commitments_info(wally_tx, i, output))

        # Get the asset-registry entries for any assets in the tx outputs
        # NOTE: must contain sufficient data for jade to be able to verify (ie. contract, issuance)
        # Not calling 'refresh_assets' here so will only use already downloaded/cached asset info
        all_assets = context.session.get_assets({'category': 'all'})['assets']
        tx_asset_ids = set(output['asset_id'] for output in transaction_outputs)
        tx_asset_info = [all_assets.get(asset_id) for asset_id in tx_asset_ids]
        tx_assets_sanitised = [asset for asset in tx_asset_info if asset and asset.get('contract') and asset.get('issuance_prevout')]

        def _mksummary(asset_amounts):
            return [{'asset_id': bytes.fromhex(asset_id), 'satoshi': satoshi} for asset_id, satoshi in asset_amounts.items()]

        additional_info = {
            'tx_type': self._get_tx_type(txtype),
            'is_partial': is_partial,
            'wallet_input_summary': _mksummary(signing_input_amounts),
            'wallet_output_summary': _mksummary(wallet_output_amounts)
        } if txtype != tx.TxType.SEND_PAYMENT else None

        # Sign!
        txn = bytes.fromhex(txhex)
        signatures = self.jade.sign_liquid_tx(self.network, txn, jade_inputs, commitments, wallet_outputs, use_ae_protocol,
                                              tx_assets_sanitised, additional_info)
        assert len(signatures) == len(transaction_inputs)

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
    return JadeAuthenticator(options)
