import click
import json

import greenaddress as gdk

from green_cli.gdk_resolve import gdk_resolve

def get_user_transaction(session, txid):
    # TODO: Iterate all pages
    # 900 is slightly arbitrary but currently the backend is limited to 30 pages of 30
    details = {'subaccount': 0, 'first': 0, 'count': 900}
    transactions = gdk_resolve(gdk.get_transactions(session.session_obj, json.dumps(details)))
    transactions = transactions['transactions']
    for transaction in transactions:
        if transaction['txhash'] == txid:
            return transaction
    raise click.ClickException("Previous transaction not found")

def add_utxos_to_transaction(session, details):
    """Add UTXOs to transaction details JSON for create_transaction"""
    # Note: We check 'private_key' here for manually built txs/future sweeping support
    if 'utxos' not in details and 'private_key' not in details:
        num_confs = 1 if 'previous_transaction' in details else 0
        utxo_details = {'subaccount': details['subaccount'], 'num_confs': num_confs}
        utxos = gdk_resolve(gdk.get_unspent_outputs(session.session_obj, json.dumps(utxo_details)))
        details['utxos'] = utxos['unspent_outputs']

def get_txhash_with_sync(session, details, wait, timeout):
    if details['error']:
        raise click.ClickException(details['error'])
    txhash = details['txhash']
    while wait:
        ntf = session.getlatestevent('transaction', timeout)
        if ntf.get('txhash', '') == txhash:
            break
    return txhash
