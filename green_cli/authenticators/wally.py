import wallycore as wally

from green_cli.authenticators import *
from typing import Tuple

import secrets
import sys

class WallyAuthenticator(MnemonicOnDisk, HardwareDevice):
    """Stores mnemonic on disk but does not pass it to the gdk

    This class illustrates how the hardware device interface to the gdk can be used to implement all
    required crypto operations external to the gdk and thus avoid passing any key material to the
    gdk at all.
    """

    def __init__(self, options):
        super().__init__(options)
        self.is_liquid = 'liquid' in options['network']

    @property
    def name(self):
        return 'libwally software signer'

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
                'supports_ae_protocol': 1,
                'supports_arbitrary_scripts': True,
                'supports_p2tr': True,
                'supports_liquid_p2tr': True,
            }
        }

    def create(self, session_obj, words):
        """Create and register a new wallet"""
        entropy_len = int(words * 4 / 3)
        entropy = secrets.token_bytes(entropy_len)

        wordlist = wally.bip39_get_wordlist('en')
        mnemonic = wally.bip39_mnemonic_from_bytes(wordlist, entropy)
        assert len(mnemonic.split()) == words

        self._mnemonic = mnemonic
        return self.register(session_obj)

    @property
    def seed(self):
        return wally.bip39_mnemonic_to_seed512(self._mnemonic, None)

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

    @property
    def master_blinding_key(self) -> bytes:
        return wally.asset_blinding_key_from_seed(self.seed)

    def get_private_blinding_key(self, script: bytes) -> bytes:
        return wally.asset_blinding_key_to_ec_private_key(self.master_blinding_key, script)

    def get_public_blinding_key(self, script: bytes) -> bytes:
        private_key = self.get_private_blinding_key(script)
        return wally.ec_public_key_from_private_key(private_key)

    def get_shared_nonce(self, pubkey: bytes, script: bytes) -> bytes:
        our_private_key = self.get_private_blinding_key(script)
        return wally.ecdh_nonce_hash(pubkey, our_private_key)

    def get_blinding_factor(self, hash_prevouts: bytes, output_index: int) -> bytes:
        return wally.asset_blinding_key_to_abf_vbf(self.master_blinding_key, hash_prevouts, output_index)

    def _make_ae_signature(self, privkey, signing_hash, details):
        # NOTE: with actual hw these two steps would be separate calls to the hww, as the host does
        #       not reveal 'host_entropy' to the signer until it has received the 'signer_commitment'.

        # 1. Provide host_commitment, receive signer_commitment
        host_commitment = bytes.fromhex(details['ae_host_commitment'])
        signer_commitment = wally.ae_signer_commit_from_bytes(privkey, signing_hash, host_commitment, wally.EC_FLAG_ECDSA)

        # 2. Provide host_entropy, receive signature
        host_entropy = bytes.fromhex(details['ae_host_entropy'])
        signature = wally.ae_sig_from_bytes(privkey, signing_hash, host_entropy, wally.EC_FLAG_ECDSA)

        return signer_commitment, signature

    def sign_message(self, details: Dict) -> Dict:
        message = details['message'].encode('utf-8')
        formatted = wally.format_bitcoin_message(message, wally.BITCOIN_MESSAGE_FLAG_HASH)
        privkey = self.get_privkey(details['path'])

        result = {}
        if details['use_ae_protocol']:
            signer_commitment, signature = self._make_ae_signature(privkey, formatted, details)
            signer_commitment = signer_commitment.hex()
            logging.debug('Signer commitment: %s', signer_commitment)
            result['signer_commitment'] = signer_commitment
        else:
            flags = wally.EC_FLAG_ECDSA | wally.EC_FLAG_GRIND_R
            signature = wally.ec_sig_from_bytes(privkey, formatted, flags)

        result['signature'] = wally.ec_sig_to_der(signature).hex()
        return result

    def _get_tx_parsing_flags(self) -> int:
        flags = wally.WALLY_TX_FLAG_USE_WITNESS
        if self.is_liquid:
            flags |= wally.WALLY_TX_FLAG_USE_ELEMENTS
        return flags

    def _validate_sighash(self, txin: Dict) -> Tuple[int, int]:
        def_sighash = wally.WALLY_SIGHASH_ALL
        allowed = [wally.WALLY_SIGHASH_ALL]
        if self.is_liquid:
            allowed.append(wally.WALLY_SIGHASH_SINGLE | wally.WALLY_SIGHASH_ANYONECANPAY)

        if txin['address_type'] == 'p2tr':
            sighash_type = wally.WALLY_SIGTYPE_SW_V1
            def_sighash = wally.WALLY_SIGHASH_DEFAULT
            allowed.append(wally.WALLY_SIGHASH_DEFAULT)
        elif txin['address_type'] in ['p2wsh', 'csv', 'p2wpkh', 'p2sh-p2wpkh']:
            sighash_type = wally.WALLY_SIGTYPE_SW_V0
        else:
            sighash_type = wally.WALLY_SIGTYPE_PRE_SW

        sighash = txin.get('user_sighash', def_sighash)
        assert sighash in allowed, f'unsupported sighash {sighash}'
        return sighash, sighash_type

    def _get_signature_hash(self, tx: object, index: int, txin: Dict,
                            sighash: int, sighash_type: int,
                            scripts: Optional[object],
                            assets: Optional[object],
                            values: Optional[object],
                            cache: object) -> bytes:

        key_version, codesep_pos, annex = 0, wally.WALLY_NO_CODESEPARATOR, None
        genesis = None
        if self.is_liquid:
            genesis = bytes.fromhex(self.default_net_params['genesis_hash'])[::-1]
        script = None
        if sighash_type != wally.WALLY_SIGTYPE_SW_V1:
            script = bytes.fromhex(txin['prevout_script'])

        return wally.tx_get_input_signature_hash(
            tx, index, scripts, assets, values, script, key_version,
            codesep_pos, annex, genesis, sighash, sighash_type, cache)

    def _sign_tx(self, details, tx):

        transaction_inputs = details['transaction_inputs']
        num_inputs = len(transaction_inputs)
        use_ae_protocol = details['use_ae_protocol']

        # Fetch signing data from each inputs UTXO
        cache = wally.map_init(16, None)
        scripts = wally.map_init(num_inputs, None)
        assets = wally.map_init(num_inputs, None) if self.is_liquid else None
        values = wally.map_init(num_inputs, None)

        for index, txin in enumerate(transaction_inputs):
            scriptpubkey = bytes.fromhex(txin.get('scriptpubkey', ''))
            if scriptpubkey:
                wally.map_add_integer(scripts, index, scriptpubkey)
            if self.is_liquid:
                asset_commitment = bytes.fromhex(txin.get('asset_tag', ''))
                if asset_commitment:
                    wally.map_add_integer(assets, index, asset_commitment)
                value = bytes.fromhex(txin.get('commitment', ''))
                if not value:
                    value = wally.tx_confidential_value_from_satoshi(txin['satoshi'])
            else:
                # Satoshi value (as uint64 native-endian bytes)
                value = txin['satoshi'].to_bytes(8, byteorder=sys.byteorder)
            wally.map_add_integer(values, index, value)

        signatures = []
        signer_commitments = []
        for index, txin in enumerate(transaction_inputs):
            if txin.get('skip_signing', False):
                # Not signing this input (may not belong to this signer)
                logging.debug(f'Not signing input {index}: skip_signing=True')
                if use_ae_protocol:
                    signer_commitments.append('')
                signatures.append('')
                continue

            # Compute the signature hash to sign
            sighash, sighash_type = self._validate_sighash(txin)
            signature_hash = self._get_signature_hash(
                tx, index, txin, sighash, sighash_type, scripts, assets, values, cache)

            # Derive the key to sign with. In a real HWW implementation
            # this would verify the path belongs to the wallet
            privkey = self.get_privkey(txin['user_path'])
            logging.debug('Processing input %s, path %s', index, txin['user_path'])

            # Sign the transaction
            signer_commitment = bytes()
            is_p2tr = sighash_type == wally.WALLY_SIGTYPE_SW_V1
            if is_p2tr or not use_ae_protocol:
                # Standard or Taproot signature
                sig_flags = wally.EC_FLAG_ECDSA | wally.EC_FLAG_GRIND_R
                if is_p2tr:
                    # Taproot Schnorr signature, low-R grinding does not apply
                    sig_flags = wally.EC_FLAG_SCHNORR
                    # Tweak the private key according to BIP-0341 (No script path)
                    tweak_flags = wally.EC_FLAG_ELEMENTS if self.is_liquid else 0
                    privkey = wally.ec_private_key_bip341_tweak(privkey, None, tweak_flags)

                signature = wally.ec_sig_from_bytes(privkey, signature_hash, sig_flags)
            else:
                # Anti-Exfil signing
                signer_commitment, signature = self._make_ae_signature(privkey, signature_hash, txin)
                logging.debug('Signer commitment: %s', signer_commitment.hex())

            if use_ae_protocol:
                # Add the signer commitment (or blank for taproot)
                signer_commitments.append(signer_commitment.hex())

            if is_p2tr:
                # Taproot: Return a 64 byte Schnorr signature, or a
                # 64 byte Schnorr signature plus non-default sighash type
                if sighash != wally.WALLY_SIGHASH_DEFAULT:
                    signature.append(sighash)
            else:
                # ECDSA: Return a DER encoded signature plus sighash
                signature = wally.ec_sig_to_der(signature)
                signature.append(sighash)

            logging.debug('%s signature: %s',
                          'Schnorr' if is_p2tr else 'ECDSA', signature.hex())
            signatures.append(signature.hex())

        result = {'signer_commitments': signer_commitments} if use_ae_protocol else {}
        result['signatures'] = signatures
        return result

    def sign_tx(self, details: Dict) -> Dict:
        flags = self._get_tx_parsing_flags()
        tx = wally.tx_from_hex(details['transaction'], flags)
        return json.dumps(self._sign_tx(details, tx))


def get_authenticator(options: Dict):
    return WallyAuthenticator(options)
