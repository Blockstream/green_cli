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


