import json
import logging
import os
from enum import Enum
from collections import defaultdict

import click

import wallycore as wally
import green_gdk as gdk

from green_cli import context
from green_cli.gdk_resolve import gdk_resolve
from green_cli.green import green
from green_cli.utils import (
    add_utxos_to_transaction,
    get_txhash_with_sync,
    get_user_transaction,
)
from green_cli.decorators import (
    confs_str,
    details_json,
    format_output,
    with_login,
)
from green_cli.param_types import (
    Address,
    Amount,
)

# Deduced tx type
TxType = Enum('TxType', ['SEND_PAYMENT', 'SWAP', 'UNKNOWN'])  # TODO: COINJOIN, etc.

# Collate satoshi total per asset
def get_asset_amounts(utxos):
    asset_amounts = defaultdict(lambda: 0)
    for utxo in utxos:
        asset_amounts[utxo.get('asset_id', 'btc')] += utxo['satoshi']
    return asset_amounts

# Deduce tx type from inspecting inputs and ouptuts.
# Currently only works for sign_transaction details.
def get_tx_type(tx):
    wallet_inputs = [i for i in tx['transaction_inputs'] if 'user_path' in i]
    wallet_outputs = [output for output in tx['transaction_outputs'] if 'user_path' in output]
    wallet_input_assets = get_asset_amounts(wallet_inputs)
    wallet_output_assets = get_asset_amounts(wallet_outputs)

    # We recognise a simple send (includes redeposit/send-to-self) tx if:
    # a) the transaction is complete (ie. not 'partial')
    # b) all the inputs belong to this wallet/signer
    # c) for each asset, the net amounts in the outputs into the wallet are not
    #    greater than the net amounts in the inputs from the wallet
    if not tx.get('is_partial', False) and \
            wallet_inputs and len(wallet_inputs) == len(tx['transaction_inputs']) and \
            not any(outsats > wallet_input_assets.get(asset, 0) for asset, outsats in wallet_output_assets.items()):
        return TxType.SEND_PAYMENT

    # We treat tx as a swap (potentially incomplete/partial) if:
    # a) the wallet has both inputs and non-change outputs, and
    # b) multiple assets are involved in the wallets inputs and outputs, and
    # c) and the wallet's outputs contain more of at least one asset than
    #    is present in the wallet's inputs for that asset
    if wallet_inputs and any(not output.get('is_change', False) for output in wallet_outputs) and \
            len(set(wallet_input_assets.keys()).union(wallet_output_assets.keys())) > 1 and \
            any(outsats > wallet_input_assets.get(asset, 0) for asset, outsats in wallet_output_assets.items()):
        return TxType.SWAP

    # TODO: coinjoin/payjoin, etc.

    # Unrecognised atm
    return TxType.UNKNOWN

def _get_tx_filename(txid):
    tx_path = os.path.join(context.config_dir, 'tx')
    os.makedirs(tx_path, exist_ok=True)
    return os.path.join(tx_path, txid)

def _load_tx(txid='scratch', allow_errors=False):
    with open(_get_tx_filename(txid), 'r') as f:
        raw_tx = f.read()
        tx = json.loads(raw_tx)
        if tx['error'] and not allow_errors:
            raise click.ClickException(tx['error'])
    return tx

def _save_tx(tx, txid='scratch'):
    with open(_get_tx_filename(txid), 'w') as f:
        f.write(json.dumps(tx))
    return tx

def _add_input_address(utxo):
    utxo['address'] = ''
    transaction = get_user_transaction(context.session, utxo['subaccount'], utxo['txhash'])
    for output in transaction['outputs']:
        if output['pt_idx'] == utxo['pt_idx']:
            utxo['address'] = output['address']
    if not utxo['address']:
        print("Did not find address for utxo")

def _add_input_addresses(tx):
    for asset in tx['utxos']:
        for utxo in tx['utxos'][asset]:
            _add_input_address(utxo)
    for tx_input in tx['transaction_inputs']:
        _add_input_address(tx_input)

def _create_tx(tx):
    add_utxos_to_transaction(context.session, tx)
    tx = gdk_resolve(gdk.create_transaction(context.session.session_obj, json.dumps(tx)))
    return tx

def _print_tx_summary(tx):
    click.echo(f"utxo strategy: {tx['utxo_strategy']}")
    click.echo(f"is_partial: {tx.get('is_partial', False)}")
    click.echo(f"randomize_inputs: {tx['randomize_inputs']}")
    click.echo(f"available inputs: {tx['available_total']}")
    input_sum = sum([utxo['satoshi'] for tx_input in tx['transaction_inputs']])
    click.echo(f"selected inputs: {input_sum}")
    click.echo(f"total outputs: {tx['satoshi']['btc']}")
    click.echo(f"change: {tx['change_amount']['btc']}")
    click.echo(f"vsize: {tx['transaction_vsize']}")
    click.echo(f"weight: {tx['transaction_weight']}")
    click.echo(f"fee: {tx['fee']}")
    click.echo(f"fee rate: {tx['calculated_fee_rate']} sat/kb")

@green.group(invoke_without_command=True)
@click.pass_context
def tx(ctx):
    """Create transactions."""
    if ctx.invoked_subcommand:
        return

    tx = _load_tx(allow_errors=True)
    if tx['error']:
        click.echo(f"ERROR: {tx['error']}")

    if 'txhash' in tx:
        click.echo(f"txhash: {tx['txhash']}")

    _print_tx_summary(tx)

@tx.command()
def raw():
    """Get the raw transaction hex."""
    click.echo(_load_tx(allow_errors=False)['transaction'])

@tx.command()
def dump():
    """Dump the full transaction json representation."""
    click.echo(format_output(_load_tx(allow_errors=True)))

@tx.command()
@with_login
@click.option('--version', type=click.Choice(['0', '2']), default='0', help="PSBT version")
def dumppsbt(session, version):
    """Dump the full transaction representation as a PSBT/PSET."""
    details = _load_tx(allow_errors=False)
    details = gdk_resolve(gdk.psbt_from_json(session.session_obj, json.dumps(details)))
    if details.get('error', ''):
        raise click.ClickException(details['error'])
    psbt = details['psbt']
    if version == '0':
        # User wants a v0 PSBT, convert it
        psbt = wally.psbt_from_base64(psbt, 0)
        wally.psbt_set_version(psbt, 0, int(version))
        psbt = wally.psbt_to_base64(psbt, 0)
    click.echo(psbt)

@tx.command()
@click.argument('tx_json', type=click.File('r'))
@with_login
def load(session, tx_json):
    """Load a transaction from json.

    Combined with dump and appropriate json manipulation tools facilitates arbitrary manipulation of
    the json representation of the current transaction. Advanced feature - use with caution.
    """
    raw_tx = tx_json.read()
    tx = json.loads(raw_tx)
    _save_tx(_create_tx(tx))

class Tx:
    """Provides context manager for loading a tx, modifying it and then saving it again."""

    def __init__(self, allow_errors=False, recreate=True):
        self.allow_errors = allow_errors
        self.recreate = recreate

    def __enter__(self):
        self._tx = _load_tx(allow_errors=self.allow_errors)
        return self._tx

    def __exit__(self, type, value, traceback):
        if self.recreate:
            self._tx = _create_tx(self._tx)
        self._tx = _save_tx(self._tx)
        return False

@tx.command()
@with_login
@click.option('--subaccount', default=0, expose_value=False, callback=details_json)
def new(session, details):
    """Create a new transaction.

    Deletes any current transaction."""
    tx = _create_tx(details)
    _add_input_addresses(tx)
    return _save_tx(tx)

@tx.command()
@with_login
@click.argument('feerate', type=int)
def setfeerate(session, feerate):
    """Set the fee rate (satoshi/kB)."""
    with Tx(allow_errors=True) as tx:
        tx['fee_rate'] = feerate

@tx.command()
@with_login
@click.argument('version', type=int)
def setversion(session, version):
    """Set the version number of the created transaction."""
    with Tx(allow_errors=True) as tx:
        tx['transaction_version'] = version

@tx.command()
@with_login
@click.argument('locktime', type=int)
def setlocktime(session, locktime):
    """Set the transaction locktime of the created transaction."""
    with Tx(allow_errors=True) as tx:
        tx['transaction_locktime'] = locktime

@tx.command()
@with_login
@click.argument('randomize-inputs', type=bool)
def setrandomizeinputs(session, randomize_inputs):
    """Set whether the created transaction should have its inputs randomized."""
    with Tx(allow_errors=True) as tx:
        tx['randomize_inputs'] = randomize_inputs

@tx.command()
@with_login
@click.argument('partial', type=bool)
def setpartial(session, partial):
    """Set whether the created transaction is a partial transaction."""
    with Tx(allow_errors=True) as tx:
        tx['is_partial'] = partial

@tx.command()
@with_login
@click.argument('sign-with', type=click.Choice(['all', 'user', 'green-backend', 'user;green-backend']))
def setsignwith(session, sign_with):
    """Set the signers a transaction should be signed with."""
    with Tx(allow_errors=True) as tx:
        tx['sign_with'] = sign_with.split(';')

def _print_tx_output(options, output):
    if options['show_all'] or (output.get('is_change', False) == options['show_change']):
        fg = 'green' if output.get('is_change', False) else None
        click.secho(f"{output['satoshi']} {output['address']}", fg=fg, color=context.color())

@tx.group(invoke_without_command=True)
@with_login
@click.pass_context
@click.option('-a', '--show-all', '--all', is_flag=True)
@click.option('-c', '--show-change', '--change', is_flag=True)
def outputs(ctx, session, **options):
    """Show and modify transaction outputs.

    With no subcommand shows a summary of the current transaction outputs."""
    if ctx.invoked_subcommand:
        return

    tx = _load_tx(allow_errors=True)
    for output in tx.get('transaction_outputs', list()):
        _print_tx_output(options, output)

@outputs.command(name='add')
@with_login
@click.argument('address', type=Address(), expose_value=False)
@click.argument('amount', type=Amount(), default='0', expose_value=False)
def add_outputs(session, details, **options):
    """Add a transaction output."""
    with Tx(allow_errors=True) as tx:
        tx.setdefault('addressees', [])
        if not details['addressees'][0].get('is_greedy', False):
            if not details['addressees'][0]['satoshi']:
                raise click.ClickException('An amount must be given for non-all outputs')
        tx['addressees'].extend(details['addressees'])

@outputs.command()
@with_login
@click.argument('address-or-index', type=str)
def rm(session, address_or_index):
    """Remove transaction outputs matching an address or from a zero-based index."""
    with Tx(allow_errors=True) as tx:
        addressees = tx.get('addressees', [])
        if addressees:
            try:
                # If address is an index, remove it
                addressees.pop(int(address_or_index))
            except IndexError as e:
                pass  # Ignore any index beyond the end
            except ValueError as e:
                # Otherwise, remove matching address string (if any)
                addressees = [a for a in addressees if a['address'] != address_or_index]
        tx['addressees'] = addressees

@outputs.command()
@with_login
def clear(session):
    """Remove all transaction outputs."""
    with Tx(allow_errors=True) as tx:
        tx['addressees'] = []

def _filter_utxos(utxo_filter, utxos):
    selected = []
    txhash, sep, pt_idx = utxo_filter.partition(':')
    address = utxo_filter if not sep else None
    for utxo in utxos:
        if address and address == utxo.get('address', None):
            selected.append(utxo)
            continue
        if txhash in ('*', 'all', utxo['txhash']):
            if pt_idx in ('', '*', 'all', str(utxo['pt_idx'])):
                selected.append(utxo)
    return selected

def format_utxo(utxo):
    confs = confs_str(utxo['block_height'])
    s = f"{utxo['satoshi']}"
    s += f" {utxo['txhash']}:{utxo['pt_idx']} {utxo['address_type']} {confs} {utxo['address']}"
    return s

@tx.group(invoke_without_command=True)
@with_login
@click.pass_context
@click.option('-a', '--show-all', '--all', is_flag=True)
@click.option('-u', '--show-unused', '--unused', is_flag=True)
def inputs(ctx, session, show_all, show_unused):
    """Show and modify transaction inputs.

    With no subcommand shows a summary of the current transaction inputs."""
    if ctx.invoked_subcommand:
        return

    tx = _load_tx(allow_errors=True)

    if show_all or not show_unused:
        for tx_input in tx['transaction_inputs']:
            click.echo(f"{format_utxo(tx_input)}")

    if show_all or show_unused:
        for asset, utxos in tx['utxos'].items():
            for utxo in utxos:
                if not _filter_utxos(f"{utxo['txhash']}:{utxo['pt_idx']}", tx['transaction_inputs']):
                    click.secho(f"{format_utxo(utxo)}", fg='red', color=context.color())

@inputs.command()
@with_login
def auto(session):
    """Enable automatic coin selection.

    Disregards any previous manual selections and reverts to automatic (default) selection.
    """
    with Tx(allow_errors=True) as tx:
        tx['utxo_strategy'] = 'default'

@inputs.command()
@with_login
@click.argument('utxo_filter')
@click.option('--sighash', type=click.Choice(['DEFAULT', 'ALL', 'S_ACP']), default='DEFAULT', help="SIGHASH type")
def add(session, utxo_filter, sighash):
    """Add transaction inputs."""
    user_sighash = {
        'DEFAULT': wally.WALLY_SIGHASH_DEFAULT,
        'ALL': wally.WALLY_SIGHASH_ALL,
        'S_ACP': wally.WALLY_SIGHASH_SINGLE | wally.WALLY_SIGHASH_ANYONECANPAY
    }[sighash]
    with Tx(allow_errors=True) as tx:
        tx['utxo_strategy'] = 'manual'
        filtered = []
        for asset in tx['utxos']:
            filtered.extend(_filter_utxos(utxo_filter, tx['utxos'][asset]))
        if not filtered:
            raise click.ClickException(f"No inputs match {utxo_filter}")
        to_add = [utxo for utxo in filtered if not _filter_utxos(f"{utxo['txhash']}:{utxo['pt_idx']}", tx['transaction_inputs'])]
        if not to_add:
            raise click.ClickException("Inputs already selected")
        for utxo in to_add:
            utxo_sighash = user_sighash
            if utxo_sighash == wally.WALLY_SIGHASH_DEFAULT and utxo['address_type'] != 'p2tr':
                # The default sighash for non-taproot inputs is SIGHASH_ALL
                utxo_sighash = wally.WALLY_SIGHASH_ALL
            utxo['user_sighash'] = utxo_sighash
        tx['transaction_inputs'].extend(to_add)

@inputs.command()
@with_login
@click.argument('utxo_filter')
def rm(session, utxo_filter):
    """Remove transaction inputs."""
    with Tx(allow_errors=True) as tx:
        tx['utxo_strategy'] = 'manual'
        filtered = _filter_utxos(utxo_filter, tx['transaction_inputs'])
        if not filtered:
            raise click.ClickException(f"No selected inputs match {utxo_filter}")
        for utxo in filtered:
            tx['transaction_inputs'].remove(utxo)

@inputs.command()
@with_login
def clear(session):
    """Remove all transaction inputs."""
    with Tx(allow_errors=True) as tx:
        tx['utxo_strategy'] = 'manual'
        tx['transaction_inputs'] = []

@tx.command()
@with_login
def blind(session):
    """Blind the current transaction. Does nothing for non-liquid transactions. """
    if 'liquid' in context.options['network']:
        with Tx(allow_errors=False, recreate=False) as tx:
            blinded = gdk_resolve(gdk.blind_transaction(session.session_obj, json.dumps(tx)))
            tx.clear()
            tx.update(blinded)

@tx.command()
@with_login
def sign(session):
    """Sign the current transaction. For Liquid, blinds first if not blinded. """
    with Tx(allow_errors=False, recreate=False) as tx:
        if 'liquid' in context.options['network'] and not tx.get('is_blinded', False):
            blinded = gdk_resolve(gdk.blind_transaction(session.session_obj, json.dumps(tx)))
            if blinded['error']:
                raise click.ClickException(blinded['error'])
        else:
            blinded = tx
        signed = gdk_resolve(gdk.sign_transaction(session.session_obj, json.dumps(blinded)))
        tx.clear()
        tx.update(signed)

@tx.command()
@with_login
@click.option('--timeout', default=0, type=int, help='Maximum number of seconds to wait')
def send(session, timeout):
    """Send the current transaction."""
    with Tx(allow_errors=False, recreate=False) as tx:
        sent = gdk_resolve(gdk.send_transaction(session.session_obj, json.dumps(tx)))
        tx.clear()
        tx.update(sent)
        txhash = get_txhash_with_sync(session, sent, timeout)
        click.echo(txhash)

@tx.command()
@with_login
@click.option('--timeout', default=0, type=int, help='Maximum number of seconds to wait')
def broadcast(session, timeout):
    """broadcast the current transaction directly to the network."""
    with Tx(allow_errors=False, recreate=False) as tx:
        sent = gdk_resolve(gdk.broadcast_transaction(session.session_obj, json.dumps(tx)))
        tx.clear()
        tx.update(sent)
        txhash = get_txhash_with_sync(session, sent, timeout)
        click.echo(txhash)
