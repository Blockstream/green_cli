"""Command line interface for green gdk"""
import atexit
import collections
import functools
import fileinput
import importlib
import json
import logging
import os
import queue
import sys

from typing import Dict, List

import click
from click_repl import register_repl

import greenaddress as gdk

from green_cli.authenticators.default import DefaultAuthenticator
from green_cli.authenticators.watchonly import WatchOnlyAuthenticator
from green_cli.param_types import (
    Address,
    Amount
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

class Context:
    """Holds global context related to the invocation of the tool"""

    def __init__(self, session, twofac_resolver, authenticator, options):
        self.session = session
        self.twofac_resolver = twofac_resolver
        self.authenticator = authenticator

        self.__dict__.update(options)

        self.logged_in = False

context = None

class TwoFactorResolver:
    """Resolves two factor authentication via the console"""

    @staticmethod
    def select_auth_factor(factors: List[str]) -> str:
        """Given a list of auth factors prompt the user to select one and return it"""
        if len(factors) > 1:
            for i, factor in enumerate(factors):
                print("{}) {}".format(i, factor))
            return factors[int(input("Select factor: "))]
        return factors[0]

    @staticmethod
    def resolve(details: Dict[str, str]):
        """Prompt the user for a 2fa code"""
        if details['method'] == 'gauth':
            msg = "Enter Google Authenticator 2fa code for action '{}': ".format(details['action'])
        else:
            msg = "Enter 2fa code for action '{}' sent by {} ({} attempts remaining): ".format(
                details['action'], details['method'], details['attempts_remaining'])
        return input(msg)


def _gdk_resolve(auth_handler):
    """Resolve a GA_auth_handler

    GA_auth_handler instances are returned by some gdk functions. They represent a state machine
    that drives the process of interacting with the user for two factor authentication or
    authentication using some external (hardware) device.
    """
    while True:
        status = gdk.auth_handler_get_status(auth_handler)
        status = json.loads(status)
        logging.debug('auth handler status = %s', status)
        state = status['status']
        logging.debug('auth handler state = %s', state)
        if state == 'error':
            raise RuntimeError(status)
        if state == 'done':
            logging.debug('auth handler returning done')
            return status['result']
        if state == 'request_code':
            # request_code only applies to 2fa requests
            authentication_factor = context.twofac_resolver.select_auth_factor(status['methods'])
            logging.debug('requesting code for %s', authentication_factor)
            gdk.auth_handler_request_code(auth_handler, authentication_factor)
        elif state == 'resolve_code':
            # resolve_code covers two different cases: a request for authentication data from some
            # kind of authentication device, for example a hardware wallet (but could be some
            # software implementation) or a 2fa request
            if status['device']:
                logging.debug('resolving auth handler with authentication device')
                resolution = context.authenticator.resolve(status)
            else:
                logging.debug('resolving two factor authentication')
                resolution = context.twofac_resolver.resolve(status)
            logging.debug('auth handler resolved: %s', resolution)
            gdk.auth_handler_resolve_code(auth_handler, resolution)
        elif state == 'call':
            gdk.auth_handler_call(auth_handler)

def _format_output(value):
    """Return pretty string representation of value suitable for displaying

    Typically value is a Dict in which case it is pretty printed
    """
    indent, separators = (None, (',', ':')) if context.compact else (2, None)
    # The strip('"') here is for non-json str outputs, for example getnewaddress, which would
    # otherwise be formatted by json.dumps with enclosing double quotes
    return json.dumps(value, indent=indent, separators=separators).strip('"')

def print_result(fn):
    """Print the result of a function to the console

    Decorator to attach to functions that return some value to display to the user
    """
    @functools.wraps(fn)
    def inner(*args, **kwargs):
        click.echo(_format_output(fn(*args, **kwargs)))
    return inner

def gdk_resolve(fn):
    """Resolve the result of a function call as a GA_auth_handler"""
    @functools.wraps(fn)
    def inner(*args, **kwargs):
        result = fn(*args, **kwargs)
        return _gdk_resolve(result)
    return inner

def with_session(fn):
    """Pass a session to a function"""
    @functools.wraps(fn)
    def inner(*args, **kwargs):
        return fn(context.session, *args, **kwargs)
    return inner

def no_warn_sysmsg(fn):
    """Suppress system message warnings on login"""
    @functools.wraps(fn)
    def inner(*args, **kwargs):
        context.no_warn_sysmsg = True
        return fn(*args, **kwargs)
    return inner

def with_login(fn):
    """Pass a logged in session to a function"""
    @functools.wraps(fn)
    def inner(session, *args, **kwargs):
        if not context.logged_in:
            logging.info("Logging in")
            result = context.authenticator.login(session.session_obj)
            # authenticator.login attempts to abstract the actual login method, it may call
            # GA_login, GA_login_with_pin or GA_login_watch_only
            # Unfortunately only GA_login returns an auth_handler, so both cases must be handled
            if result:
                _gdk_resolve(result)
            context.logged_in = True

            if not context.no_warn_sysmsg:
                # Show the user a prompt to read and acknowledge outstanding system messages
                system_message = gdk.get_system_message(session.session_obj)
                if system_message:
                    click.echo("You have unread system messages, please call getsystemmessages")

        return fn(session, *args, **kwargs)
    return with_session(inner)

def get_authenticator(options):
    """Return an object that implements the authentication interface"""
    auth_module = importlib.import_module('green_cli.authenticators.{}'.format(options['auth']))
    logging.debug("using auth module {}".format(auth_module))
    return auth_module.get_authenticator(options['network'], options['config_dir'])

class Session(gdk.Session):

    def __init__(self, net_params):
        super().__init__( net_params)

    def callback_handler(self, event):
        logging.debug("Callback received event: {}".format(event))
        try:
            if event['event'] == 'network' and event['network'].get('login_required', False):
                logging.debug("Setting logged_in to false after network event")
                context.logged_in = False
        except Exception as e:
            logging.error("Error processing event: {}".format(str(e)))

        super().callback_handler(event)

def _get_config_dir(options):
    """Return the default config dir for network"""
    return os.path.expanduser(os.path.join('~', '.green-cli', options['network']))

@click.group()
@click.option('--log-level', type=click.Choice(['error', 'warning', 'info', 'debug']))
@click.option('--gdk-log', default='none', type=click.Choice(['none', 'debug', 'warn', 'info', 'fatal']))
@click.option('--network', default='localtest', help='Network: localtest|testnet|mainnet.')
@click.option('--auth', default='default', type=click.Choice(['default', 'hardware', 'wally', 'watchonly']))
@click.option('--config-dir', '-C', default=None, help='Override config directory.')
@click.option('--compact', '-c', is_flag=True, help='Compact json output (no pretty printing)')
@click.option('--watch-only', is_flag=True, help='Use watch-only login')
@click.option('--tor', is_flag=True, help='Use tor for external connections')
@click.option('--no-warn-sysmsg', is_flag=True, help='Suppress warning about unread system messages')
@click.option('--expert', is_flag=True, hidden=True)
def green(**options):
    """Command line interface for green gdk"""
    global context
    if context is not None:
        # Retain context over multiple commands in repl mode
        return

    session_params = {
        'name': options['network'],
        'use_tor': options['tor'],
        'log_level': options['gdk_log'],
    }

    if options['log_level']:
        py_log_level = {
            'error': logging.ERROR,
            'warning': logging.WARNING,
            'info': logging.INFO,
            'debug': logging.DEBUG,
        }[options['log_level']]

        logging.basicConfig(level=py_log_level)

    if options['config_dir'] is None:
        options['config_dir'] = _get_config_dir(options)
    try:
        os.makedirs(options['config_dir'])
    except FileExistsError:
        pass

    gdk.init({})
    session = Session(session_params)
    atexit.register(session.destroy)

    if options['watch_only']:
        options['auth'] = 'watchonly'

    authenticator = get_authenticator(options)
    context = Context(session, TwoFactorResolver(), authenticator, options)

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
@gdk_resolve
def create(session):
    """Create a new wallet"""
    if _get_network()['mainnet'] and not context.expert:
        # Disable create on mainnet
        # To make this safe clients usually implement some mechanism to check that the user has
        # correctly stored their mnemonic before proceeding.
        raise click.ClickException("Wallet creation on mainnet disabled")
    return context.authenticator.create(session.session_obj)

@green.command()
@with_session
@gdk_resolve
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

        _gdk_resolve(gdk.ack_system_message(session.session_obj, message))

@green.command()
@with_login
def listen(session):
    """Listen for notifications

    Wait indefinitely for notifications from the gdk and print then to the console. ctrl-c to stop
    """
    while True:
        try:
            click.echo(_format_output(session.notifications.get(block=True, timeout=1)))
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

def details_json(ctx, param, value):
    """Add an option/parameter to details json

    For many commands options translate directly into elements in a json 'details' input parameter
    to the gdk method. Adding this method as a click.argument callback appends a details json to
    make this convenient.
    """
    if value is not None:
        details = ctx.params.setdefault('details', collections.OrderedDict())
        # hyphens are idiomatic for command line args, so allow some_option to be passed as
        # some-option
        name = param.name.replace("-", "_")
        details[name] = value
    return value

@green.command()
@click.argument('name', expose_value=False, callback=details_json)
@click.argument('type', type=click.Choice(['2of2', '2of3']), expose_value=False, callback=details_json)
@click.option('--recovery-mnemonic', type=str, expose_value=False, callback=details_json)
@click.option('--recovery-xpub', type=str, expose_value=False, callback=details_json)
@with_login
@print_result
@gdk_resolve
def createsubaccount(session, details):
    """Create a subaccount"""
    return gdk.create_subaccount(session.session_obj, json.dumps(details))

@green.command()
@with_login
@print_result
@gdk_resolve
def getsubaccounts(session):
    return gdk.get_subaccounts(session.session_obj)

@green.command()
@click.argument('pointer', type=int)
@with_login
@print_result
@gdk_resolve
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
@gdk_resolve
def setnlocktime(session, details):
    """Set number of blocks for nlocktime"""
    return gdk.set_nlocktime(session.session_obj, json.dumps(details))

@green.command()
@click.argument('value', type=int, expose_value=False, callback=details_json)
@with_login
@gdk_resolve
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
@gdk_resolve
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
    return _gdk_resolve(auth_handler)["address"]

@green.command()
@click.option('--subaccount', default=0, expose_value=False, callback=details_json)
@click.option('--address_type', default="", expose_value=False, callback=details_json)
@with_login
@print_result
@gdk_resolve
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
@gdk_resolve
def getbalance(session, details):
    """Get balance"""
    return gdk.get_balance(session.session_obj, json.dumps(details))

@green.command()
@click.option('--subaccount', default=0, expose_value=False, callback=details_json)
@click.option('--num-confs', default=0, expose_value=False, callback=details_json)
@with_login
@print_result
@gdk_resolve
def getunspentoutputs(session, details):
    """Get unspent outputs"""
    return gdk.get_unspent_outputs(session.session_obj, json.dumps(details))

@green.command()
@click.option('--subaccount', type=int, default=0, expose_value=False, callback=details_json)
@click.option('--first', type=int, default=0, expose_value=False, callback=details_json)
@click.option('--count', type=int, default=30, expose_value=False, callback=details_json)
@with_login
@print_result
@gdk_resolve
def gettransactions(session, details):
    return gdk.get_transactions(session.session_obj, json.dumps(details))

@green.command()
@click.option('--addressee', '-a', type=(Address(), Amount()), expose_value=False, multiple=True)
@click.option('--subaccount', default=0, expose_value=False, callback=details_json)
@click.option('--fee-rate', '-f', type=int, expose_value=False, callback=details_json)
@with_login
@print_result
def createtransaction(session, details):
    """Create an outgoing transaction"""
    return _gdk_resolve(gdk.create_transaction(session.session_obj, json.dumps(details)))

@green.command()
@click.argument('details', type=click.File('rb'))
@with_login
@print_result
@gdk_resolve
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
@gdk_resolve
def sendtransaction(session, details):
    """Send a transaction

    Send a transaction previously returned by signtransaction. TXDETAILS can be a filename or - to
    read from standard input, e.g.

    $ green createtransaction -a <address> 1000 | green signtransaction - | green sendtransaction -
    """
    details = details.read().decode('utf-8')
    return gdk.send_transaction(session.session_obj, details)

def _send_transaction(session, details):
    details = _gdk_resolve(gdk.create_transaction(session.session_obj, json.dumps(details)))
    details = _gdk_resolve(gdk.sign_transaction(session.session_obj, json.dumps(details)))
    details = _gdk_resolve(gdk.send_transaction(session.session_obj, json.dumps(details)))
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
    transactions = _gdk_resolve(gdk.get_transactions(session.session_obj, json.dumps(details)))
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

@green.group(name="2fa")
def twofa():
    """Two-factor authentication"""

@twofa.command()
@with_login
@print_result
def getconfig(session):
    """Print two-factor authentication configuration"""
    return session.get_twofactor_config()

@twofa.group(name="enable")
def enabletwofa():
    """Enable an authentication factor"""

def _enable_2fa(session, factor, data):
    details = {'confirmed': True, 'enabled': True, 'data': data}
    logging.debug("_enable_2fa factor='{}', details={}".format(factor, details))
    return gdk.change_settings_twofactor(session.session_obj, factor, json.dumps(details))

@enabletwofa.command()
@click.argument('email_address')
@with_login
@gdk_resolve
def email(session, email_address):
    """Enable email 2fa"""
    return _enable_2fa(session, 'email', email_address)

@enabletwofa.command()
@click.argument('number')
@with_login
@gdk_resolve
def sms(session, number):
    """Enabled SMS 2fa"""
    return _enable_2fa(session, 'sms', number)

@enabletwofa.command()
@click.argument('number')
@with_login
@gdk_resolve
def phone(session, number):
    """Enable phone 2fa"""
    return _enable_2fa(session, 'phone', number)

@enabletwofa.command()
@with_login
@gdk_resolve
def gauth(session):
    """Enable gauth 2fa"""
    data = session.get_twofactor_config()['gauth']['data']
    key = data.partition('secret=')[2]
    click.echo('Google Authenticator key: {}'.format(key))
    return _enable_2fa(session, 'gauth', data)

@twofa.command()
@click.argument('factor', type=click.Choice(['email', 'sms', 'phone', 'gauth']))
@with_login
@gdk_resolve
def disable(session, factor):
    """Disable an authentication factor"""
    details = {'confirmed': True, 'enabled': False}
    return gdk.change_settings_twofactor(session.session_obj, factor, json.dumps(details))

@twofa.command()
@click.argument('threshold', type=str)
@click.argument('key', type=str)
@with_login
@gdk_resolve
def setthreshold(session, threshold, key):
    """Set the two-factor threshold"""
    is_fiat = key == 'fiat'
    details = {'is_fiat': is_fiat, key: threshold}
    return gdk.twofactor_change_limits(session.session_obj, json.dumps(details))

@twofa.group(name="reset")
def twofa_reset():
    """Two-factor authentication reset"""

@twofa_reset.command()
@click.argument('reset_email')
@with_login
@gdk_resolve
def request(session, reset_email):
    """Request a 2fa reset"""
    is_dispute = False
    return gdk.twofactor_reset(session.session_obj, reset_email, is_dispute)

@twofa_reset.command()
@click.argument('reset_email')
@with_login
@gdk_resolve
def dispute(session, reset_email):
    """Dispute a 2fa reset"""
    is_dispute = True
    return gdk.twofactor_reset(session.session_obj, reset_email, is_dispute)

@twofa_reset.command()
@with_login
@gdk_resolve
def cancel(session):
    """Cancel a 2fa reset"""
    return gdk.twofactor_cancel_reset(session.session_obj)

def main():
    register_repl(green)
    green()

if __name__ == "__main__":
    main()
