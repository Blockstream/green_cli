"""Code common to green-cli and green-liquid-cli."""
import collections
import fileinput
import functools
import json
import logging
import queue

import click
from click_repl import register_repl
from datetime import datetime, timezone

import greenaddress as gdk

from green_cli import context
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
from green_cli.utils import (
    add_utxos_to_transaction,
    get_txhash_with_sync,
    get_user_transaction,
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
    """Show all available networks."""
    return gdk.get_networks()

@functools.lru_cache(maxsize=None)
def _get_network():
    return gdk.get_networks()[context.network]

@green.command()
@print_result
def getnetwork():
    """Show details of current network.

    As determined by the --network option.
    """
    return _get_network()

@green.command()
@click.option('--words', type=click.Choice(['12', '24']), default='24', help="Mnemonic length")
@with_session
@with_gdk_resolve
def create(session, words):
    """Create a new wallet."""
    if not getattr(context.authenticator, 'create', None):
        raise click.ClickException("{} does not support creating new wallets".format(context.authenticator.name))

    if _get_network()['mainnet'] and not context.expert:
        # Disable create on mainnet
        # To make this safe clients usually implement some mechanism to check that the user has
        # correctly stored their mnemonic before proceeding.
        raise click.ClickException("Wallet creation on mainnet disabled")

    return context.authenticator.create(session.session_obj, int(words))

@green.command()
@with_login
@with_gdk_resolve
def removeaccount(session):
    """Remove the wallet/account completely.

    Wallet must be empty."""
    return gdk.remove_account(session.session_obj)

@green.command()
@with_session
@with_gdk_resolve
def register(session):
    """Register an existing wallet."""
    return context.authenticator.register(session.session_obj)

@green.command()
@no_warn_sysmsg
@with_login
def getsystemmessages(session):
    """Get unread system messages."""
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
@click.argument('event_type')
@click.option('--timeout', default=None, type=int, help='Maximum number of seconds to wait')
@print_result
def getlatestevent(session, event_type, timeout):
    """Get the most recent of some event type.

    Will wait if necessary until the first such event arrrives, if no timeout is given.

    Useful events include 'block' and 'fees', for example:

    # Get the latest reported block height

    $ green-cli getlatestevent block | jq .block_height
    123

    # Get the minimum fee rate

    $ green-cli getlatestevent fees | jq .[0]
    1000
    """
    return session.getlatestevent(event_type, timeout)

@green.command()
@with_login
@click.option('--ignore', type=str, help='Comma delimited list of events to ignore, e.g. "block,fees"')
def listen(session, ignore):
    """Listen for notifications.

    Wait indefinitely for notifications from the gdk and print then to the console. ctrl-c to stop.
    """
    ignore = [s.strip() for s in ignore.split(',')] if ignore else []
    while True:
        try:
            n = session.notifications.get(block=True, timeout=1)
            if n.get('event', None) in ignore:
                logging.debug("Ignoring filtered notification")
            else:
                click.echo(format_output(n))
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
    """Show an amount in different units."""
    # satoshi is unfortunately different from the others as it is an int, not a str
    amount = int(amount) if unit == 'satoshi' else amount
    return session.convert_amount({unit: amount})

_SUBACCOUNT_TYPES = ['2of2', '2of3', 'p2pkh', 'p2sh-p2wpkh', 'p2wpkh']

@green.command()
@click.argument('name', expose_value=False, callback=details_json)
@click.argument('type', type=click.Choice(_SUBACCOUNT_TYPES), expose_value=False, callback=details_json)
@click.option('--recovery-mnemonic', type=str, expose_value=False, callback=details_json)
@click.option('--recovery-xpub', type=str, expose_value=False, callback=details_json)
@with_login
@print_result
@with_gdk_resolve
def createsubaccount(session, details):
    """Create a subaccount."""
    return gdk.create_subaccount(session.session_obj, json.dumps(details))

@green.command()
@click.option('--refresh', is_flag=True, help='Refresh cached values', expose_value=False, callback=details_json)
@with_login
@print_result
@with_gdk_resolve
def getsubaccounts(session, details):
    """Show all subaccounts for the wallet."""
    return gdk.get_subaccounts(session.session_obj, json.dumps(details))

@green.command()
@click.argument('pointer', type=int)
@with_login
@print_result
@with_gdk_resolve
def getsubaccount(session, pointer):
    """Show details of specific subaccount."""
    return gdk.get_subaccount(session.session_obj, pointer)

@green.command()
@click.option('--subaccount', default=0, expose_value=False, callback=details_json)
@click.option('--name', expose_value=False, callback=details_json)
@click.option('--hidden', type=bool, expose_value=False, callback=details_json)
@with_login
@with_gdk_resolve
def updatesubaccount(session, details):
    return gdk.update_subaccount(session.session_obj, json.dumps(details))

@green.command()
@click.argument('pin')
@click.argument('device_id')
@with_login
def setpin(session, pin, device_id):
    """Set a PIN for logging in.

    Replace the locally stored plaintext mnemonic with one encrypted with a PIN.

    The key to decrypt the mnemonic is stored on the server and will be permanently deleted after
    too many PIN attempts.
    """
    return context.authenticator.setpin(session, pin, device_id)

@green.command()
@click.option('--password', default="", expose_value=False, callback=details_json)
@with_login
@print_result
@with_gdk_resolve
def getcredentials(session, details):
    """Get the wallet credentials.

    If password is not empty, it is used to bip38-encrypt the mnemonic.
    """
    return gdk.get_credentials(session.session_obj, json.dumps(details))

@green.command()
@click.argument('username')
@click.argument('password')
@with_login
def setwatchonly(session, username, password):
    """Enable watch-only login with the supplied username and password."""
    return session.set_watch_only(username, password)

@green.command()
@with_login
def disablewatchonly(session):
    """Disable watch-only logins for the wallet."""
    return session.set_watch_only('', '')

@green.command()
@with_login
def sendnlocktimes(session):
    """Send an encrypted nlocktimes zip to the wallet's email address."""
    return gdk.send_nlocktimes(session.session_obj)

@green.command()
@click.argument('value', type=int, expose_value=False, callback=details_json)
@with_login
@with_gdk_resolve
def setnlocktime(session, details):
    """Set number of blocks for nlocktime."""
    return gdk.set_nlocktime(session.session_obj, json.dumps(details))

@green.command()
@click.argument('value', type=int, expose_value=False, callback=details_json)
@with_login
@with_gdk_resolve
def setcsvtime(session, details):
    """Set number of blocks for csvtime."""
    return gdk.set_csvtime(session.session_obj, json.dumps(details))

@green.command()
@click.argument('txid', type=str)
@click.argument('memo', type=str)
@click.option('--bip70', is_flag=True, help='Set a bip70 memo')
@with_login
def settransactionmemo(session, txid, memo, bip70):
    """Set a memo on a wallet transaction."""
    memo_type = gdk.GA_MEMO_BIP70 if bip70 else gdk.GA_MEMO_USER
    return gdk.set_transaction_memo(session.session_obj, txid, memo, memo_type)

@green.command()
@with_login
@print_result
def getwatchonly(session):
    """Get watch-only login details."""
    return session.get_watch_only_username()

@green.command()
@with_login
@print_result
def getavailablecurrencies(session, txid):
    """Get supported currencies and their associated pricing source."""
    return session.get_available_currencies()

@green.command()
@with_login
@print_result
def getsettings(session):
    """Print wallet settings."""
    return session.get_settings()

@green.command()
@click.argument('settings', type=click.File('rb'))
@with_login
@with_gdk_resolve
def changesettings(session, settings):
    """Change wallet settings."""
    settings = settings.read().decode('utf-8')
    return gdk.change_settings(session.session_obj, settings)

@green.command()
@with_login
@print_result
def getavailablecurrencies(session):
    """Get available currencies."""
    return session.get_available_currencies()

@green.command()
@click.option('--subaccount', default=0, expose_value=False, callback=details_json)
@click.option('--address_type', default="", expose_value=False, callback=details_json)
@with_login
@print_result
def getnewaddress(session, details):
    """Get a new receive address."""
    auth_handler = gdk.get_receive_address(session.session_obj, json.dumps(details))
    return gdk_resolve(auth_handler)["address"]

@green.command()
@click.option('--subaccount', default=0, expose_value=False, callback=details_json)
@click.option('--address_type', default="", expose_value=False, callback=details_json)
@with_login
@print_result
@with_gdk_resolve
def getreceiveaddress(session, details):
    """Get a new receive address."""
    return gdk.get_receive_address(session.session_obj, json.dumps(details))

@green.command()
@click.option('--subaccount', default=0, expose_value=False, callback=details_json)
@click.option('--last-pointer', type=int, expose_value=False, callback=details_json)
@click.option('--is-internal', is_flag=True, expose_value=False, callback=details_json)
@with_login
@print_result
@with_gdk_resolve
def getpreviousaddresses(session, details):
    """Get previously generated addresses."""
    return gdk.get_previous_addresses(session.session_obj, json.dumps(details))

@green.command()
@with_login
@print_result
def getfeeestimates(session):
    """Get fee estimates."""
    return session.get_fee_estimates()

@green.command()
@click.option('--subaccount', default=0, expose_value=False, callback=details_json)
@click.option('--num-confs', default=0, expose_value=False, callback=details_json)
@click.option('--all-coins', is_flag=True, expose_value=False, callback=details_json)
@click.option('--expired-at', type=int, expose_value=False, callback=details_json)
@click.option('--dust-limit', type=int, expose_value=False, callback=details_json)
@with_login
@print_result
@with_gdk_resolve
def getbalance(session, details):
    """Get balance."""
    return gdk.get_balance(context.session.session_obj, json.dumps(details))

@green.command()
@click.option('--subaccount', default=0, expose_value=False, callback=details_json)
@click.option('--num-confs', default=0, expose_value=False, callback=details_json)
@click.option('--all-coins', is_flag=True, expose_value=False, callback=details_json)
@click.option('--expired-at', type=int, expose_value=False, callback=details_json)
@click.option('--dust-limit', type=int, expose_value=False, callback=details_json)
@with_login
@print_result
@with_gdk_resolve
def getunspentoutputs(session, details):
    """Get unspent outputs (utxos)."""
    return gdk.get_unspent_outputs(session.session_obj, json.dumps(details))

@green.command()
@click.argument('privatekey', type=str)
@click.argument('password', default='')
@with_login
@print_result
def getunspentoutputsforprivatekey(session, privatekey, password):
    return session.get_unspent_outputs_for_private_key(privatekey, password, 0)

@green.command()
@click.argument('status', type=(UtxoUserStatus()), expose_value=False, nargs=-1)
@with_login
@print_result
@with_gdk_resolve
def setunspentoutputsstatus(session, details):
    """Set unspent outputs status.

    Status format is <txid>:<vout>:[default|frozen]
    """
    return gdk.set_unspent_outputs_status(session.session_obj, json.dumps(details))

def _txlist_summary(txlist):
    txns = sorted(txlist['transactions'], key=lambda tx: tx['created_at_ts'])
    balance = collections.defaultdict(int)
    lines = []
    for tx in txns:
        confs = confs_str(tx['block_height'])
        fee_rate = tx['fee'] / tx['transaction_vsize']
        for asset, amount in tx['satoshi'].items():
            balance[asset] += amount
            ts = tx['created_at_ts']
            created_at = datetime.fromtimestamp(ts // 1000000, tz=timezone.utc).replace(tzinfo=None)
            lines.append(f"{tx['txhash']} {created_at} ({confs}) {amount:+} "\
                f"{balance[asset]} {asset} fee={tx['fee']}@{fee_rate:.2f}")
    return '\n'.join(lines)

@green.command()
@click.argument('txid', type=str)
@with_login
@print_result
def gettransactiondetails(session, txid):
    """Get transaction details of an arbitrary transaction."""
    return session.get_transaction_details(txid)

@green.command()
@click.option('--subaccount', type=int, default=0, expose_value=False, callback=details_json)
@click.option('--first', type=int, default=0, expose_value=False, callback=details_json)
@click.option('--count', type=int, default=30, expose_value=False, callback=details_json)
@click.option('--summary', is_flag=True, help='Print human-readable summary')
@with_login
def gettransactions(session, summary, details):
    """Get transactions associated with the wallet."""
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
    """Create an outgoing transaction."""
    add_utxos_to_transaction(session, details)
    return gdk_resolve(gdk.create_transaction(session.session_obj, json.dumps(details)))

@green.command()
@click.argument('details', type=click.File('rb'))
@with_login
@print_result
@with_gdk_resolve
def signtransaction(session, details):
    """Sign a transaction.

    Pass in the transaction details json from createtransaction. TXDETAILS can be a filename or - to
    read from standard input, e.g.

    $ green createtransaction -a <address> 1000 | green signtransaction -
    """
    details = details.read().decode('utf-8')
    return gdk.sign_transaction(session.session_obj, details)

@green.command()
@click.argument('details', type=click.File('rb'))
@click.option('--wait', is_flag=True, help='Wait for the transaction notification before returning')
@click.option('--timeout', default=None, type=int, help='Maximum number of seconds to wait')
@with_login
@print_result
def sendtransaction(session, details, wait, timeout):
    """Send a transaction.

    Send a transaction previously returned by signtransaction. TXDETAILS can be a filename or - to
    read from standard input, e.g.

    $ green createtransaction -a <address> 1000 | green signtransaction - | green sendtransaction -
    """
    details = details.read().decode('utf-8')
    details = gdk_resolve(gdk.send_transaction(session.session_obj, json.dumps(details)))
    return get_txhash_with_sync(session, details, wait, timeout)

def _send_transaction(session, details, wait, timeout):
    add_utxos_to_transaction(session, details)
    details = gdk_resolve(gdk.create_transaction(session.session_obj, json.dumps(details)))
    if details['error']:
        raise click.ClickException(details['error'])
    details = gdk_resolve(gdk.sign_transaction(session.session_obj, json.dumps(details)))
    if details['error']:
        raise click.ClickException(details['error'])
    details = gdk_resolve(gdk.send_transaction(session.session_obj, json.dumps(details)))
    return get_txhash_with_sync(session, details, wait, timeout)

@green.command()
@click.argument('address', type=Address(), expose_value=False)
@click.argument('amount', type=Amount(precision=8), expose_value=False)
@click.option('--subaccount', default=0, expose_value=False, callback=details_json)
@click.option('--wait', is_flag=True, help='Wait for the transaction notification before returning')
@click.option('--timeout', default=None, type=int, help='Maximum number of seconds to wait')
@with_login
@print_result
def sendtoaddress(session, details, wait, timeout):
    """Send funds to an address."""
    return _send_transaction(session, details, wait, timeout)

@green.command()
@click.argument('previous_txid', type=str)
@click.argument('fee_multiplier', default=2, type=float)
@click.option('--subaccount', default=0, type=int)
@click.option('--wait', is_flag=True, help='Wait for the transaction notification before returning')
@click.option('--timeout', default=None, type=int, help='Maximum number of seconds to wait')
@with_login
@print_result
def bumpfee(session, previous_txid, fee_multiplier, subaccount, wait, timeout):
    """Increase the fee of an unconfirmed transaction."""
    previous_transaction = get_user_transaction(session, previous_txid)
    if not previous_transaction['can_rbf']:
        raise click.ClickException("Previous transaction not replaceable")
    details = {'previous_transaction': previous_transaction}
    details['subaccount'] = subaccount
    details['fee_rate'] = int(previous_transaction['fee_rate'] * fee_multiplier)
    return _send_transaction(session, details, wait, timeout)

@green.group()
def set():
    """Set local options."""

@set.command()
@click.argument('username', type=str)
def username(username):
    """Set username to use for watch-only login."""
    WatchOnlyAuthenticator(context.options).set_username(username)

@set.command()
@click.argument('password', type=str)
def password(password):
    """Set password to use for watch-only login."""
    WatchOnlyAuthenticator(context.options).set_password(password)

@set.command()
@click.argument('jade_serial_device', type=str)
def jadeusbserialdevice(jade_serial_device):
    from green_cli.authenticators.jade import JadeAuthenticator
    JadeAuthenticator(context.options).set_usb_serial_device(jade_serial_device)

@set.command()
@click.argument('jade_ble_serial_number', type=str)
def jadebleserialnumber(jade_ble_serial_number):
    from green_cli.authenticators.jade import JadeAuthenticator
    JadeAuthenticator(context.options).set_ble_serial_number(jade_ble_serial_number)

@set.command()
@click.option('--file', '-f', 'file_', is_flag=True, help='Read mnemonic from file')
@click.argument('mnemonic', type=str)
def mnemonic(file_, mnemonic):
    """Set the mnemonic for the wallet.

    This command will store the mnemonic locally and use it to log in to Green.
    """
    if file_:
        mnemonic = fileinput.input(mnemonic).readline()
    DefaultAuthenticator(context.options).set_mnemonic(mnemonic)

def main():
    register_repl(green)
    green()
