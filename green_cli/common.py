"""Code common to green-cli and green-liquid-cli."""
import atexit
import collections
import functools
import fileinput
import json
import logging
import os
import queue
import sys

import click
from click_repl import register_repl

import greenaddress as gdk

import green_cli
from . import context

from green_cli.green import green

from green_cli.gdk_resolve import gdk_resolve
from green_cli.decorators import (
    confs_str,
    details_json,
    format_output,
    with_gdk_resolve,
    no_warn_sysmsg,
    print_result,
    with_login,
    with_session,
)
from green_cli.authenticators.default import DefaultAuthenticator
from green_cli.authenticators.watchonly import WatchOnlyAuthenticator
from green_cli.param_types import (
    Address,
    Amount,
    UtxoUserStatus,
)

# In older verions of python (<3.6?) json.loads does not respect the order of the input
# unless specifically passed object_pairs_hook=collections.OrderedDict
# Monkey patch here to force consistent ordering on all python versions (otherwise for example every
# time you call getbalance the keys will be in an arbitrarily different order in the output).
_json_loads = json.loads
def ordered_json_loads(*args, **kwargs):
    kwargs['object_pairs_hook'] = collections.OrderedDict
    return _json_loads(*args, **kwargs)
json.loads = ordered_json_loads

@green.command()
@print_result
def getnetworks():
    return gdk.get_networks()

def _get_network():
    return gdk.get_networks()[context.network]

@green.command()
@print_result
def getnetwork():
    return _get_network()

@green.command()
@with_session
@with_gdk_resolve
def create(session):
    """Create a new wallet"""
    if _get_network()['mainnet'] and not context.expert:
        # Disable create on mainnet
        # To make this safe clients usually implement some mechanism to check that the user has
        # correctly stored their mnemonic before proceeding.
        raise click.ClickException("Wallet creation on mainnet disabled")
    return context.authenticator.create(session.session_obj)

@green.command()
@with_login
@with_gdk_resolve
def removeaccount(session):
    """Remove the wallet/account completely. Wallet must be empty"""
    return gdk.remove_account(session.session_obj)

@green.command()
@with_session
@with_gdk_resolve
def register(session):
    """Register an existing wallet"""
    return context.authenticator.register(session.session_obj)

@green.command()
@no_warn_sysmsg
@with_login
def getsystemmessages(session):
    """Get unread system messages"""
    while True:
        message = gdk.get_system_message(session.session_obj)
        if not message:
            break

        click.echo("--- MESSAGE STARTS ---")
        click.echo(message)
        click.echo("--- MESSAGE ENDS ---")
        if not click.confirm("Mark message as read (sign and send acknowledgement to the server)?"):
            break

        gdk_resolve(gdk.ack_system_message(session.session_obj, message))

@green.command()
@with_login
def listen(session):
    """Listen for notifications

    Wait indefinitely for notifications from the gdk and print then to the console. ctrl-c to stop
    """
    while True:
        try:
            click.echo(format_output(session.notifications.get(block=True, timeout=1)))
        except queue.Empty:
            logging.debug("queue.Empty, passing")
            pass
        except KeyboardInterrupt:
            logging.debug("KeyboardInterrupt during listen, returning")
            break

@green.command()
@with_login
@click.argument('amount', type=str)
@click.argument('unit', type=click.Choice(['bits', 'btc', 'mbtc', 'ubtc', 'satoshi', 'sats']))
@print_result
def convertamount(session, amount, unit):
    # satoshi is unfortunately different from the others as it is an int, not a str
    amount = int(amount) if unit == 'satoshi' else amount
    return session.convert_amount({unit: amount})

@green.command()
@click.argument('name', expose_value=False, callback=details_json)
@click.argument('type', type=click.Choice(['2of2', '2of3']), expose_value=False, callback=details_json)
@click.option('--recovery-mnemonic', type=str, expose_value=False, callback=details_json)
@click.option('--recovery-xpub', type=str, expose_value=False, callback=details_json)
@with_login
@print_result
@with_gdk_resolve
def createsubaccount(session, details):
    """Create a subaccount"""
    return gdk.create_subaccount(session.session_obj, json.dumps(details))

@green.command()
@with_login
@print_result
@with_gdk_resolve
def getsubaccounts(session):
    return gdk.get_subaccounts(session.session_obj)

@green.command()
@click.argument('pointer', type=int)
@with_login
@print_result
@with_gdk_resolve
def getsubaccount(session, pointer):
    return gdk.get_subaccount(session.session_obj, pointer)

@green.command()
@click.argument('pointer', type=int)
@click.argument('name', type=str)
@with_login
def renamesubaccount(session, pointer, name):
    return session.rename_subaccount(pointer, name)

@green.command()
@click.argument('pin')
@click.argument('device_id')
@with_login
def setpin(session, pin, device_id):
    """Replace the locally stored plaintext mnemonic with one encrypted with a PIN

    The key to decrypt the mnemonic is stored on the server and will be permanently deleted after
    too many PIN attempts.
    """
    return context.authenticator.setpin(session, pin, device_id)

@green.command()
@click.argument('password', type=str, default='')
@with_login
@print_result
def getmnemonic(session, password):
    """Get the wallet mnemonic

    If password is not empty, it is used to bip38-encrypt the mnemonic.
    """
    return session.get_mnemonic_passphrase(password)

@green.command()
@click.argument('username')
@click.argument('password')
@with_login
def setwatchonly(session, username, password):
    """Set watch-only login details"""
    return session.set_watch_only(username, password)

@green.command()
@click.argument('value', type=int, expose_value=False, callback=details_json)
@with_login
@with_gdk_resolve
def setnlocktime(session, details):
    """Set number of blocks for nlocktime"""
    return gdk.set_nlocktime(session.session_obj, json.dumps(details))

@green.command()
@click.argument('value', type=int, expose_value=False, callback=details_json)
@with_login
@with_gdk_resolve
def setcsvtime(session, details):
    """Set number of blocks for csvtime"""
    return gdk.set_csvtime(session.session_obj, json.dumps(details))

@green.command()
@click.argument('txid', type=str)
@click.argument('memo', type=str)
@click.option('--bip70', is_flag=True, help='Set a bip70 memo')
@with_login
def settransactionmemo(session, txid, memo, bip70):
    """Set a memo on a wallet transaction"""
    memo_type = gdk.GA_MEMO_BIP70 if bip70 else gdk.GA_MEMO_USER
    return gdk.set_transaction_memo(session.session_obj, txid, memo, memo_type)

@green.command()
@with_login
@print_result
def getwatchonly(session):
    """Get watch-only login details"""
    return session.get_watch_only_username()

@green.command()
@with_login
@print_result
def getsettings(session):
    """Print wallet settings"""
    return session.get_settings()

@green.command()
@click.argument('settings', type=click.File('rb'))
@with_login
@with_gdk_resolve
def changesettings(session, settings):
    """Change wallet settings"""
    settings = settings.read().decode('utf-8')
    return gdk.change_settings(session.session_obj, settings)

@green.command()
@with_login
@print_result
def getavailablecurrencies(session):
    """Get available currencies"""
    return session.get_available_currencies()

@green.command()
@click.option('--subaccount', default=0, expose_value=False, callback=details_json)
@click.option('--address_type', default="", expose_value=False, callback=details_json)
@with_login
@print_result
def getnewaddress(session, details):
    """Get a new receive address"""
    auth_handler = gdk.get_receive_address(session.session_obj, json.dumps(details))
    return gdk_resolve(auth_handler)["address"]

@green.command()
@click.option('--subaccount', default=0, expose_value=False, callback=details_json)
@click.option('--address_type', default="", expose_value=False, callback=details_json)
@with_login
@print_result
@with_gdk_resolve
def getreceiveaddress(session, details):
    """Get a new receive address"""
    return gdk.get_receive_address(session.session_obj, json.dumps(details))

@green.command()
@with_login
@print_result
def getfeeestimates(session):
    """Get fee estimates"""
    return session.get_fee_estimates()

@green.command()
@click.option('--subaccount', default=0, expose_value=False, callback=details_json)
@click.option('--num-confs', default=0, expose_value=False, callback=details_json)
@with_login
@print_result
@with_gdk_resolve
def getbalance(session, details):
    """Get balance"""
    return gdk.get_balance(context.session.session_obj, json.dumps(details))

@green.command()
@click.option('--subaccount', default=0, expose_value=False, callback=details_json)
@click.option('--num-confs', default=0, expose_value=False, callback=details_json)
@click.option('--all-coins', type=bool, default=False, expose_value=False, callback=details_json)
@with_login
@print_result
@with_gdk_resolve
def getunspentoutputs(session, details):
    """Get unspent outputs"""
    return gdk.get_unspent_outputs(session.session_obj, json.dumps(details))

@green.command()
@click.argument('status', type=(UtxoUserStatus()), expose_value=False, nargs=-1)
@with_login
@print_result
@with_gdk_resolve
def setunspentoutputsstatus(session, details):
    """Set unspent outputs status. Status format is <txid>:<vout>:[default|frozen]"""
    return gdk.set_unspent_outputs_status(session.session_obj, json.dumps(details))

def _txlist_summary(txlist):
    txns = sorted(txlist['transactions'], key=lambda tx: tx['created_at'])
    balance = collections.defaultdict(int)
    lines = []
    for tx in txns:
        confs = confs_str(tx['block_height'])
        fee_rate = tx['fee'] / tx['transaction_vsize']
        if tx['type'] == 'outgoing':
            # Currently only supports txs which are all one-way
            tx['satoshi'] = {asset: -tx['satoshi'][asset] for asset in tx['satoshi']}
        for asset, amount in tx['satoshi'].items():
            balance[asset] += amount
            lines.append(f"{tx['txhash']} {tx['created_at']} ({confs}) {amount:+} "\
                f"{balance[asset]} {asset} fee={tx['fee']}@{fee_rate:.2f}")
    return '\n'.join(lines)

@green.command()
@click.option('--subaccount', type=int, default=0, expose_value=False, callback=details_json)
@click.option('--first', type=int, default=0, expose_value=False, callback=details_json)
@click.option('--count', type=int, default=30, expose_value=False, callback=details_json)
@click.option('--summary', is_flag=True, help='Print human-readable summary')
@with_login
def gettransactions(session, summary, details):
    result = gdk.get_transactions(session.session_obj, json.dumps(details))
    result = gdk_resolve(result)
    result = _txlist_summary(result) if summary else format_output(result)
    click.echo(result)

@green.command()
@click.option('--addressee', '-a', type=(Address(), Amount()), expose_value=False, multiple=True)
@click.option('--subaccount', default=0, expose_value=False, callback=details_json)
@click.option('--fee-rate', '-f', type=int, expose_value=False, callback=details_json)
@with_login
@print_result
def createtransaction(session, details):
    """Create an outgoing transaction"""
    return gdk_resolve(gdk.create_transaction(session.session_obj, json.dumps(details)))

@green.command()
@click.argument('details', type=click.File('rb'))
@with_login
@print_result
@with_gdk_resolve
def signtransaction(session, details):
    """Sign a transaction

    Pass in the transaction details json from createtransaction. TXDETAILS can be a filename or - to
    read from standard input, e.g.

    $ green createtransaction -a <address> 1000 | green signtransaction -
    """
    details = details.read().decode('utf-8')
    return gdk.sign_transaction(session.session_obj, details)

@green.command()
@click.argument('details', type=click.File('rb'))
@with_login
@print_result
@with_gdk_resolve
def sendtransaction(session, details):
    """Send a transaction

    Send a transaction previously returned by signtransaction. TXDETAILS can be a filename or - to
    read from standard input, e.g.

    $ green createtransaction -a <address> 1000 | green signtransaction - | green sendtransaction -
    """
    details = details.read().decode('utf-8')
    return gdk.send_transaction(session.session_obj, details)

def _send_transaction(session, details):
    details = gdk_resolve(gdk.create_transaction(session.session_obj, json.dumps(details)))
    details = gdk_resolve(gdk.sign_transaction(session.session_obj, json.dumps(details)))
    details = gdk_resolve(gdk.send_transaction(session.session_obj, json.dumps(details)))
    return details['txhash']

@green.command()
@click.argument('address', type=Address(), expose_value=False)
@click.argument('amount', type=Amount(precision=8), expose_value=False)
@click.option('--subaccount', default=0, expose_value=False, callback=details_json)
@with_login
@print_result
def sendtoaddress(session, details):
    return _send_transaction(session, details)

def _get_transaction(session, txid):
    # TODO: Iterate all pages
    # 900 is slightly arbitrary but currently the backend is limited to 30 pages of 30
    details = {'subaccount': 0, 'first': 0, 'count': 900}
    transactions = gdk_resolve(gdk.get_transactions(session.session_obj, json.dumps(details)))
    transactions = transactions['transactions']
    for transaction in transactions:
        if transaction['txhash'] == txid:
            return transaction
    raise click.ClickException("Previous transaction not found")

@green.command()
@click.argument('previous_txid', type=str)
@click.argument('fee_multiplier', default=2, type=float)
@with_login
@print_result
def bumpfee(session, previous_txid, fee_multiplier):
    """Increase the fee of an unconfirmed transaction (RBF)"""
    previous_transaction = _get_transaction(session, previous_txid)
    if not previous_transaction['can_rbf']:
        raise click.ClickException("Previous transaction not replaceable")
    details = {'previous_transaction': previous_transaction}
    details['subaccount'] = 0 # FIXME ?
    details['fee_rate'] = int(previous_transaction['fee_rate'] * fee_multiplier)
    return _send_transaction(session, details)

@green.group()
def set():
    """Set local options"""

@set.command()
@click.argument('username', type=str)
def username(username):
    WatchOnlyAuthenticator(context.config_dir).set_username(username)

@set.command()
@click.argument('password', type=str)
def password(password):
    WatchOnlyAuthenticator(context.config_dir).set_password(password)

@set.command()
@click.option('--file', '-f', 'file_', is_flag=True, help='Read mnemonic from file')
@click.argument('mnemonic', type=str)
def mnemonic(file_, mnemonic):
    if file_:
        mnemonic = fileinput.input(mnemonic).readline()
    DefaultAuthenticator(context.config_dir).set_mnemonic(mnemonic)

def main():
    register_repl(green)
    green()
