"""Code common to Bitcoin and Liquid networks."""
import collections
import fileinput
import functools
import json
import logging
import queue

import click
from click_repl import register_repl
from datetime import datetime, timezone

import green_gdk as gdk

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
from green_cli.notifications import notifications
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
@with_session
@with_gdk_resolve
@click.option('--words', type=click.Choice(['12', '24']), default='24', help="Mnemonic length")
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
@click.option('--words', type=click.Choice(['12', '24']), default='24', help="Mnemonic length")
def generatemnemonic(words):
    """Generate and print a new mnemonic.

    Should only be used for testing or on an air-gapped device."""
    fn = gdk.generate_mnemonic if words == '24' else gdk.generate_mnemonic_12
    click.echo(fn())

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
@print_result
@click.option('--timeout', default=-1, type=int, help='Maximum number of seconds to wait')
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
@print_result
def getnextevent(session):
    """Get the next queued notification, if any.

    Does not wait, returns an empty JSON document if no notifications remain.

    This command is useful only in the context of a repl loop.
    """
    try:
        return session.notifications.get(block=False)
    except queue.Empty:
        return dict()

@green.command()
@with_login
@click.option('--ignore', type=str, help='Comma delimited list of events to ignore, e.g. "block,fees"')
def listen(session, ignore):
    """Listen for notifications.

    Wait indefinitely for notifications from the gdk and print then to the console. ctrl-c to stop.
    """
    ignore = [s.strip() for s in ignore.split(',')] if ignore else []
    for n in notifications(session):
        if n.get('event', None) in ignore:
            logging.debug("Ignoring filtered notification")
        else:
            click.echo(format_output(n))

@green.command()
@with_login
@print_result
@click.argument('amount', type=str)
@click.argument('unit', type=click.Choice(['bits', 'btc', 'mbtc', 'ubtc', 'satoshi', 'sats']))
def convertamount(session, amount, unit):
    """Show an amount in different units."""
    # satoshi is unfortunately different from the others as it is an int, not a str
    amount = int(amount) if unit == 'satoshi' else amount
    return session.convert_amount({unit: amount})

_SUBACCOUNT_TYPES = ['2of2', '2of3', 'p2pkh', 'p2sh-p2wpkh', 'p2wpkh', 'p2tr']

@green.command()
@with_login
@print_result
@with_gdk_resolve
@click.argument('name', expose_value=False, callback=details_json)
@click.argument('type', type=click.Choice(_SUBACCOUNT_TYPES), expose_value=False, callback=details_json)
@click.option('--recovery-mnemonic', type=str, expose_value=False, callback=details_json)
@click.option('--recovery-xpub', type=str, expose_value=False, callback=details_json)
def createsubaccount(session, details):
    """Create a subaccount."""
    return gdk.create_subaccount(session.session_obj, json.dumps(details))

@green.command()
@with_login
@print_result
@with_gdk_resolve
@click.option('--refresh', is_flag=True, help='Refresh cached values', expose_value=False, callback=details_json)
def getsubaccounts(session, details):
    """Show all subaccounts for the wallet."""
    return gdk.get_subaccounts(session.session_obj, json.dumps(details))

@green.command()
@with_login
@print_result
@with_gdk_resolve
@click.argument('subaccount', type=int)
def getsubaccount(session, subaccount):
    """Show details of specific subaccount."""
    return gdk.get_subaccount(session.session_obj, subaccount)

@green.command()
@with_login
@with_gdk_resolve
@click.argument('subaccount', type=int, expose_value=False, callback=details_json)
@click.option('--name', expose_value=False, callback=details_json)
@click.option('--hidden', type=bool, expose_value=False, callback=details_json)
def updatesubaccount(session, details):
    return gdk.update_subaccount(session.session_obj, json.dumps(details))

@green.command()
@with_login
@print_result
@with_gdk_resolve
@click.option('--action', expose_value=False, callback=details_json)
@click.option('--data-source', expose_value=False, callback=details_json)
def cachecontrol(session, details):
    return gdk.cache_control(session.session_obj, json.dumps(details))

@green.command()
@with_login
@click.argument('pin')
@click.argument('device_id')
def setpin(session, pin, device_id):
    """Set a PIN for logging in.

    Replace the locally stored plaintext mnemonic with one encrypted with a PIN.

    The key to decrypt the mnemonic is stored on the server and will be permanently deleted after
    three failed PIN attempts.
    """
    return context.authenticator.setpin(session, pin, device_id)

@green.command()
@with_login
@print_result
@with_gdk_resolve
@click.option('--password', default="", expose_value=False, callback=details_json)
def getcredentials(session, details):
    """Get the wallet credentials.

    If password is not empty, it is used to bip38-encrypt the mnemonic.
    """
    return gdk.get_credentials(session.session_obj, json.dumps(details))

@green.command()
@with_login
@print_result
@click.argument('username', type=str, expose_value=False, callback=details_json)
@click.argument('password', type=str, expose_value=False, callback=details_json)
@with_gdk_resolve
def setwatchonly(session, details):
    """Enable watch-only login with the supplied username and password."""
    return gdk.register_user(session.session_obj, '{}', json.dumps(details))

@green.command()
@with_login
@with_gdk_resolve
def disablewatchonly(session):
    """Disable watch-only logins for the wallet."""
    empty_credentials = json.dumps({'username': '', 'password': ''})
    return gdk.register_user(session.session_obj, '{}', empty_credentials)

@green.command()
@with_login
def sendnlocktimes(session):
    """Send an encrypted nlocktimes zip to the wallet's email address."""
    return gdk.send_nlocktimes(session.session_obj)

@green.command()
@with_login
@with_gdk_resolve
@click.argument('value', type=int, expose_value=False, callback=details_json)
def setnlocktime(session, details):
    """Set number of blocks for nlocktime."""
    return gdk.set_nlocktime(session.session_obj, json.dumps(details))

@green.command()
@with_login
@with_gdk_resolve
@click.argument('value', type=int, expose_value=False, callback=details_json)
def setcsvtime(session, details):
    """Set number of blocks for csvtime."""
    return gdk.set_csvtime(session.session_obj, json.dumps(details))

@green.command()
@with_login
@click.argument('txid', type=str)
@click.argument('memo', type=str)
def settransactionmemo(session, txid, memo):
    """Set a memo on a wallet transaction."""
    return gdk.set_transaction_memo(session.session_obj, txid, memo, gdk.GA_MEMO_USER)

@green.command()
@with_login
@print_result
def getwatchonly(session):
    """Get watch-only login details."""
    return session.get_watch_only_username()

@green.command()
@with_login
@print_result
def getavailablecurrencies(session):
    """Get supported currencies and their associated pricing source."""
    return session.get_available_currencies()

@green.command()
@with_login
@print_result
def getsettings(session):
    """Print wallet settings."""
    return session.get_settings()

@green.command()
@with_login
@with_gdk_resolve
@click.argument('settings', type=click.File('rb'))
def changesettings(session, settings):
    """Change wallet settings."""
    settings = settings.read().decode('utf-8')
    return gdk.change_settings(session.session_obj, settings)

@green.command()
@with_login
@print_result
@click.option('--subaccount', default=0, expose_value=False, callback=details_json)
@click.option('--address-type', '--address_type', default="", expose_value=False, callback=details_json)
@click.option('--ignore-gap-limit', is_flag=True, default=False, expose_value=False, callback=details_json)
def getnewaddress(session, details):
    """Get a new receive address."""
    auth_handler = gdk.get_receive_address(session.session_obj, json.dumps(details))
    return gdk_resolve(auth_handler)["address"]

@green.command()
@with_login
@print_result
@with_gdk_resolve
@click.option('--subaccount', default=0, expose_value=False, callback=details_json)
@click.option('--address-type', '--address_type', default="", expose_value=False, callback=details_json)
@click.option('--ignore-gap-limit', is_flag=True, default=False, expose_value=False, callback=details_json)
def getreceiveaddress(session, details):
    """Get a new receive address."""
    return gdk.get_receive_address(session.session_obj, json.dumps(details))

@green.command()
@with_login
@print_result
@with_gdk_resolve
@click.option('--subaccount', default=0, expose_value=False, callback=details_json)
@click.option('--last-pointer', type=int, expose_value=False, callback=details_json)
@click.option('--is-internal', is_flag=True, expose_value=False, callback=details_json)
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
@with_login
@print_result
@with_gdk_resolve
@click.option('--subaccount', default=0, expose_value=False, callback=details_json)
@click.option('--num-confs', default=0, expose_value=False, callback=details_json)
@click.option('--all-coins', is_flag=True, expose_value=False, callback=details_json)
@click.option('--expired-at', type=int, expose_value=False, callback=details_json)
@click.option('--expires-in', type=int, expose_value=False, callback=details_json)
@click.option('--dust-limit', type=int, expose_value=False, callback=details_json)
def getbalance(session, details):
    """Get balance."""
    return gdk.get_balance(context.session.session_obj, json.dumps(details))

_UTXO_SORT_TYPES = ['oldest', 'newest', 'largest', 'smallest']

@green.command()
@with_login
@print_result
@with_gdk_resolve
@click.option('--subaccount', default=0, expose_value=False, callback=details_json)
@click.option('--num-confs', default=0, expose_value=False, callback=details_json)
@click.option('--address-type', default='', expose_value=False, callback=details_json)
@click.option('--all-coins', is_flag=True, expose_value=False, callback=details_json)
@click.option('--expired-at', type=int, expose_value=False, callback=details_json)
@click.option('--expires-in', type=int, expose_value=False, callback=details_json)
@click.option('--dust-limit', type=int, expose_value=False, callback=details_json)
@click.option('--sort-by', type=click.Choice(_UTXO_SORT_TYPES), expose_value=False, callback=details_json)
def getunspentoutputs(session, details):
    """Get unspent outputs (utxos)."""
    return gdk.get_unspent_outputs(session.session_obj, json.dumps(details))


@green.command()
@with_login
@print_result
@with_gdk_resolve
@click.option('--private-key', expose_value=False, callback=details_json)
@click.option('--password', default="", expose_value=False, callback=details_json)
def getunspentoutputsforprivatekey(session, details):
    return gdk.get_unspent_outputs_for_private_key(session.session_obj, json.dumps(details))

@green.command()
@with_login
@print_result
@with_gdk_resolve
@click.argument('status', type=(UtxoUserStatus()), expose_value=False, nargs=-1)
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
            lines.append(f"{tx['txhash']} {created_at} ({confs}) {amount:+} "
                         f"{balance[asset]} {asset} fee={tx['fee']}@{fee_rate:.2f}")
    return '\n'.join(lines)

@green.command()
@with_login
@print_result
@click.argument('txid', type=str)
def gettransactiondetails(session, txid):
    """Get transaction details of an arbitrary transaction."""
    return session.get_transaction_details(txid)

@green.command()
@with_login
@click.option('--subaccount', type=int, default=0, expose_value=False, callback=details_json)
@click.option('--first', type=int, default=0, expose_value=False, callback=details_json)
@click.option('--count', type=int, default=30, expose_value=False, callback=details_json)
@click.option('--summary', is_flag=True, help='Print human-readable summary')
def gettransactions(session, summary, details):
    """Get transactions associated with the wallet."""
    result = gdk.get_transactions(session.session_obj, json.dumps(details))
    result = gdk_resolve(result)
    result = _txlist_summary(result) if summary else format_output(result)
    click.echo(result)

@green.command()
@with_login
@print_result
@with_gdk_resolve
@click.option('--addressee', '-a', type=(Address(), Amount()), expose_value=False, multiple=True)
@click.option('--subaccount', default=0, expose_value=False, callback=details_json)
@click.option('--fee-rate', '-f', type=int, expose_value=False, callback=details_json)
def createtransaction(session, details):
    """Create an outgoing transaction."""
    add_utxos_to_transaction(session, details)
    return gdk.create_transaction(session.session_obj, json.dumps(details))

@green.command()
@with_login
@print_result
@with_gdk_resolve
@click.option('--subaccount', type=int, expose_value=False, callback=details_json)
@click.option('--expired-at', type=int, expose_value=False, callback=details_json)
@click.option('--expires-in', type=int, expose_value=False, callback=details_json)
@click.option('--fee-subaccount', expose_value=False, callback=details_json, help='The subaccount to return any leftover fees too')
@click.option('--fee-rate', expose_value=False, callback=details_json, help='The fee rate to use in sat per 1000 vbytes')
def createredeposittransaction(session, details):
    """Create a redeposit transaction for a subaccounts expired UTXOs"""
    # Get the unspend outputs, sorted by oldest first
    utxo_details = {'subaccount': details['subaccount'], 'num_confs': 1}
    utxos = gdk_resolve(gdk.get_unspent_outputs(session.session_obj, json.dumps(utxo_details)))
    details['utxos'] = utxos['unspent_outputs']
    return gdk.create_redeposit_transaction(session.session_obj, json.dumps(details))

@green.command()
@with_login
@print_result
@with_gdk_resolve
@click.argument('details', type=click.File('rb'))
def blindtransaction(session, details):
    """Blind a transaction.

    Pass in the transaction details json from createtransaction. TXDETAILS can be a filename or - to
    read from standard input, e.g.

    $ green createtransaction -a <address> 1000 | green blindtransaction - | green signtransaction -
    """
    details = details.read().decode('utf-8')
    return gdk.blind_transaction(session.session_obj, details)

@green.command()
@with_login
@print_result
@with_gdk_resolve
@click.argument('details', type=click.File('rb'))
def signtransaction(session, details):
    """Sign a transaction. For Liquid, blinds first if not blinded.

    Pass in the transaction details json from createtransaction or blindtransaction.
    TXDETAILS can be a filename or - to read from standard input, e.g.

    $ green createtransaction -a <address> 1000 | green signtransaction -
    """
    details = details.read().decode('utf-8')
    if 'liquid' in context.options['network'] and not json.loads(details).get('is_blinded', False):
        details = gdk_resolve(gdk.blind_transaction(session.session_obj, details))
        if details['error']:
            raise click.ClickException(details['error'])
        details = json.dumps(details)
    return gdk.sign_transaction(session.session_obj, details)

@green.command()
@with_login
@print_result
@with_gdk_resolve
@click.argument('details', type=click.File('rb'))
def psbtsign(session, details):
    """Sign a PSBT/PSET. For Liquid, the PSET must be blinded."""
    details = details.read().decode('utf-8')
    return gdk.psbt_sign(session.session_obj, details)

@green.command()
@with_login
@print_result
@with_gdk_resolve
@click.argument('details', type=click.File('rb'))
def psbtgetdetails(session, details):
    """Get wallet information from a PSBT/PSET."""
    details = details.read().decode('utf-8')
    return gdk.psbt_get_details(session.session_obj, details)

@green.command()
@with_login
@print_result
@with_gdk_resolve
@click.argument('details', type=click.File('rb'))
def psbtfromjson(session, details):
    """Get a PSBT/PSET from the JSON output of createtransaction/signtransaction."""
    details = details.read().decode('utf-8')
    return gdk.psbt_from_json(session.session_obj, details)

@green.command()
@with_login
@print_result
@click.argument('details', type=click.File('rb'))
@click.option('--timeout', default=0, type=int, help='Maximum number of seconds to wait')
def sendtransaction(session, details, timeout):
    """Send a transaction.

    Send a transaction previously returned by signtransaction. TXDETAILS can be a filename or - to
    read from standard input, e.g.

    $ green createtransaction -a <address> 1000 | green signtransaction - | green sendtransaction -
    """
    details = details.read().decode('utf-8')
    details = gdk_resolve(gdk.send_transaction(session.session_obj, details))
    return get_txhash_with_sync(session, details, timeout)

@green.command()
@with_login
@print_result
@click.argument('details', type=click.File('rb'))
@click.option('--timeout', default=0, type=int, help='Maximum number of seconds to wait')
def broadcasttransaction(session, details, timeout):
    """Broadcast a transaction directly to the network."""
    details = details.read().decode('utf-8')
    details = gdk_resolve(gdk.broadcast_transaction(session.session_obj, details))
    get_txhash_with_sync(session, details, timeout)
    return details

def _send_transaction(session, details, timeout):
    add_utxos_to_transaction(session, details)
    steps = [gdk.create_transaction, gdk.sign_transaction, gdk.send_transaction]
    if 'liquid' in context.options['network']:
        steps.insert(1, gdk.blind_transaction)
    for step in steps:
        details = gdk_resolve(step(session.session_obj, json.dumps(details)))
        if details['error']:
            raise click.ClickException(details['error'])
    return get_txhash_with_sync(session, details, timeout)

@green.command()
@with_login
@print_result
@click.argument('address', type=Address(), expose_value=False)
@click.argument('amount', type=Amount(precision=8), expose_value=False)
@click.option('--subaccount', default=0, expose_value=False, callback=details_json)
@click.option('--timeout', default=0, type=int, help='Maximum number of seconds to wait')
def sendtoaddress(session, details, timeout):
    """Send funds to an address."""
    return _send_transaction(session, details, timeout)

@green.command()
@with_login
@print_result
@click.argument('previous_txid', type=str)
@click.argument('fee_multiplier', default=2, type=float)
@click.option('--subaccount', default=0, type=int)
@click.option('--timeout', default=0, type=int, help='Maximum number of seconds to wait')
def bumpfee(session, previous_txid, fee_multiplier, subaccount, timeout):
    """Increase the fee of an unconfirmed transaction."""
    previous_transaction = get_user_transaction(session, subaccount, previous_txid)
    if not previous_transaction['can_rbf']:
        raise click.ClickException("Previous transaction not replaceable")
    details = {'previous_transaction': previous_transaction}
    details['subaccount'] = subaccount
    details['fee_rate'] = int(previous_transaction['fee_rate'] * fee_multiplier)
    return _send_transaction(session, details, timeout)

@green.command()
@with_login
@print_result
@with_gdk_resolve
@click.argument('address', type=str, expose_value=False, callback=details_json)
@click.argument('message', type=str, expose_value=False, callback=details_json)
def signmessage(session, details):
    """Sign a message"""
    return gdk.sign_message(session.session_obj, json.dumps(details))

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
@click.argument('watch-only-data', type=str)
def watch_only_data(watch_only_data):
    """Set watch_only_data key to use for watch-only login."""
    WatchOnlyAuthenticator(context.options).set_watch_only_data(watch_only_data)

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

@green.command()
@with_session
@print_result
@with_gdk_resolve
@click.argument('pem', type=click.File('r'))
@click.argument('challenge', type=click.File('rb'))
@click.argument('signature', type=click.File('rb'))
def rsaverify(session, pem, challenge, signature):
    """Verify an RSA challenge."""
    details = {
        'pem': pem.read(),
        'challenge': challenge.read().hex(),
        'signature': signature.read().hex(),
    }
    return gdk.rsa_verify(session.session_obj, json.dumps(details))


def main():
    register_repl(green)
    green()
