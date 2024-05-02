import click
import json
import queue
import time

import green_gdk as gdk

from green_cli.gdk_resolve import gdk_resolve

def get_user_transaction(session, subaccount, txid):
    # TODO: Iterate all pages
    details = {'subaccount': subaccount, 'first': 0, 'count': 9999}
    transactions = gdk_resolve(gdk.get_transactions(session.session_obj, json.dumps(details)))
    transactions = transactions['transactions']
    for transaction in transactions:
        if transaction['txhash'] == txid:
            return transaction
    raise click.ClickException("Previous transaction not found")

def add_utxos_to_transaction(session, details):
    """Add UTXOs to transaction details JSON for create_transaction"""
    if 'transaction_inputs' not in details and 'utxos' not in details:
        num_confs = 1 if 'previous_transaction' in details else 0
        utxo_details = {'subaccount': details['subaccount'], 'num_confs': num_confs}
        utxos = gdk_resolve(gdk.get_unspent_outputs(session.session_obj, json.dumps(utxo_details)))
        details['utxos'] = utxos['unspent_outputs']

def get_txhash_with_sync(session, details, timeout, txhash=None):
    if details.get('error', ''):
        raise click.ClickException(details['error'])
    txhash = txhash or details['txhash']
    if timeout:
        # Wait for the tx notification, forever if timeout < 0, else timeout seconds
        timeout = timeout * 10
        start_time = time.time()
        while True:
            try:
                ntf = session.notifications.get(block=False)
            except queue.Empty:
                ntf = dict()
            if 'transaction' in ntf and ntf['transaction']['txhash'] == txhash:
                return txhash
            if timeout >= 0:
                timeout = timeout - (time.time() - start_time)
                if timeout <= 0:
                    raise click.ClickException(f'Timed out waiting for tx {txhash}')
                time.sleep(0.1)
    return txhash
