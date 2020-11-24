from green_cli.authenticators.wally import WallyAuthenticator

import wallycore as wally

import json
import os

class WallyAuthenticatorLiquid(WallyAuthenticator):

    @property
    def master_blinding_key(self) -> bytes:
        return wally.asset_blinding_key_from_seed(self.seed)

    def get_private_blinding_key(self, script: bytes) -> bytes:
        return wally.asset_blinding_key_to_ec_private_key(self.master_blinding_key, script)

    def get_public_blinding_key(self, script: bytes) -> bytes:
        private_key = self.get_private_blinding_key(script)
        return wally.ec_public_key_from_private_key(private_key)

    def get_shared_nonce(self, pubkey: bytes, script: bytes) -> bytes:
        our_privkey = self.get_private_blinding_key(script)
        nonce = wally.sha256(wally.ecdh(pubkey, our_privkey))
        return nonce

    def _get_blinding_factors(self, txdetails, wally_tx):
        utxos = txdetails['used_utxos'] or txdetails['old_used_utxos']
 
        for i, o in enumerate(txdetails['transaction_outputs']):
            o['wally_index'] = i

        blinded_outputs = [o for o in txdetails['transaction_outputs'] if not o['is_fee']]
        for output in blinded_outputs:
            # TODO: the derivation dance
            # the following values are in display order, reverse them when converting to bytes
            output['assetblinder'] = os.urandom(32).hex()
            output['amountblinder'] = os.urandom(32).hex()

        endpoints = utxos + blinded_outputs
        values = [endpoint['satoshi'] for endpoint in endpoints]
        abfs = b''.join(bytes.fromhex(endpoint['assetblinder'])[::-1] for endpoint in endpoints)
        vbfs = b''.join(bytes.fromhex(endpoint['amountblinder'])[::-1] for endpoint in endpoints[:-1])
        final_vbf = wally.asset_final_vbf(values, len(utxos), abfs, vbfs)
        blinded_outputs[-1]['amountblinder'] = final_vbf.hex()

        for o in blinded_outputs:
            asset_commitment = wally.asset_generator_from_bytes(bytes.fromhex(o['asset_id'])[::-1], bytes.fromhex(o['assetblinder'])[::-1])
            value_commitment = wally.asset_value_commitment(o['satoshi'], bytes.fromhex(o['amountblinder'])[::-1], asset_commitment)

            o['asset_commitment'] = asset_commitment.hex()
            o['value_commitment'] = value_commitment.hex()

            # Write the commitments into the wally tx for signing
            wally.tx_set_output_asset(wally_tx, o['wally_index'], asset_commitment)
            wally.tx_set_output_value(wally_tx, o['wally_index'], value_commitment)

        retval = {}
        for key in ['assetblinders', 'amountblinders', 'asset_commitments', 'value_commitments']:
            # gdk expects to get an empty entry for the fee output too, hence this is over the
            # transaction outputs, not just the blinded outputs (fee will just have empty
            # strings)
            retval[key] = [o.get(key[:-1], '') for o in txdetails['transaction_outputs']]
        return retval

    def _get_sighash(self, wally_tx, index, utxo):
        flags = wally.WALLY_TX_FLAG_USE_WITNESS
        prevout_script = wally.hex_to_bytes(utxo['prevout_script'])
        if utxo['confidential']:
            value = bytes.fromhex(utxo['commitment'])
        else:
            value = wally.tx_confidential_value_from_satoshi(utxo['satoshi'])
        return wally.tx_get_elements_signature_hash(
            wally_tx, index, prevout_script, value, wally.WALLY_SIGHASH_ALL, flags)

    def sign_tx(self, details):
        tx_flags = wally.WALLY_TX_FLAG_USE_WITNESS | wally.WALLY_TX_FLAG_USE_ELEMENTS
        wally_tx = wally.tx_from_hex(details['transaction']['transaction'], tx_flags)

        retval = {}
        retval.update(self._get_blinding_factors(details['transaction'], wally_tx))
        retval.update(self._sign_tx(details, wally_tx))

        return json.dumps(retval)
