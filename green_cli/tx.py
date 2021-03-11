import json
import logging
import os

import click

import greenaddress as gdk

from green_cli import context
from green_cli.gdk_resolve import gdk_resolve
from green_cli.green import green
from green_cli.utils import (
    get_transaction,
)
from green_cli.decorators import (
    confs_str,
    details_json,
    with_login,
)
from green_cli.param_types import (
    Address,
    Amount,
)

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
    transaction = get_transaction(context.session, utxo['txhash'])
    for output in transaction['outputs']:
        if output['pt_idx'] == utxo['pt_idx']:
            utxo['address'] = output['address']
    if not utxo['address']:
        print("Did not find address for utxo")

def _add_input_addresses(tx):
    for asset in tx['utxos']:
        for utxo in tx['utxos'][asset]:
            _add_input_address(utxo)
    for utxo in tx['used_utxos']:
        _add_input_address(utxo)

def _create_tx(tx):
    tx = gdk_resolve(gdk.create_transaction(context.session.session_obj, json.dumps(tx)))
    return tx

def _print_tx_summary(tx):
    click.echo(f"user signed: {tx['user_signed']}")
    click.echo(f"server signed: {tx['server_signed']}")
    click.echo(f"send all: {tx.get('send_all', False)}")
    click.echo(f"utxo strategy: {tx['utxo_strategy']}")
    click.echo(f"available inputs: {tx['available_total']}")
    click.echo(f"selected inputs: {sum([utxo['satoshi'] for utxo in tx['used_utxos']])}")
    click.echo(f"total outputs: {tx['satoshi']['btc']}")
    click.echo(f"change: {tx['change_amount']['btc']}")
    click.echo(f"size: {tx['transaction_size']}")
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
    click.echo(json.dumps(_load_tx(allow_errors=True)))

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
@click.option('--subaccount', default=0, expose_value=False, callback=details_json)
@with_login
def new(session, details):
    """Create a new transaction.

    Deletes any current transaction."""
    tx = _create_tx(details)
    _add_input_addresses(tx)
    return _save_tx(tx)

@tx.command()
@click.argument('feerate', type=int)
@with_login
def setfeerate(session, feerate):
    """Set the fee rate (satoshi/kB)."""
    with Tx(allow_errors=True) as tx:
        tx['fee_rate'] = feerate

def _print_tx_output(options, output):
    if options['show_all'] or (output['is_change'] == options['show_change']):
        fg = 'green' if output['is_change'] else None
        click.secho(f"{output['satoshi']} {output['address']}", fg=fg)

@tx.group(invoke_without_command=True)
@click.option('-a', '--show-all', '--all', is_flag=True)
@click.option('-c', '--show-change', '--change', is_flag=True)
@with_login
@click.pass_context
def outputs(ctx, session, **options):
    """Show and modify transaction outputs.

    With no subcommand shows a summary of the current transaction outputs."""
    if ctx.invoked_subcommand:
        return

    tx = _load_tx(allow_errors=True)
    for output in tx['transaction_outputs']:
        _print_tx_output(options, output)

@outputs.command(name='add')
@click.argument('address', type=Address(), expose_value=False)
@click.argument('amount', type=Amount(), expose_value=False)
@with_login
def add_outputs(session, details):
    """Add a transaction output."""
    with Tx(allow_errors=True) as tx:
        tx.setdefault('addressees', [])
        send_all = details.get('send_all', False)
        if send_all:
            if tx['addressees']:
                raise click.ClickException(
                    "Cannot add send-all output with other outputs present. "
                    "First remove other outputs with `tx outputs clear`.")
            tx['send_all'] = True
        tx['addressees'].extend(details['addressees'])

@outputs.command()
@click.argument('address', type=str)
@with_login
def rm(session, address):
    """Remove transaction outputs."""
    with Tx(allow_errors=True) as tx:
        if 'send_all' in tx:
            del tx['send_all']
        addressees = tx.get('addressees', [])
        addressees = [a for a in addressees if a['address'] != address]
        tx['addressees'] = addressees

@outputs.command()
@with_login
def clear(session):
    """Remove all transaction outputs."""
    with Tx(allow_errors=True) as tx:
        if 'send_all' in tx:
            del tx['send_all']
        tx['addressees'] = []

def _filter_utxos(utxo_filter, utxos):
    selected = []
    txhash, sep, pt_idx = utxo_filter.partition(':')
    address = utxo_filter if not sep else None
    for utxo in utxos:
        if  address and address == utxo.get('address', None):
            selected.append(utxo)
            continue
        if txhash == '*' or txhash == utxo['txhash']:
            if not pt_idx or pt_idx == '*' or int(pt_idx) == utxo['pt_idx']:
                selected.append(utxo)
    return selected

def format_utxo(utxo):
    confs = confs_str(utxo['block_height'])
    s = f"{utxo['satoshi']}"
    s += f" {utxo['txhash']}:{utxo['pt_idx']} {utxo['address_type']} {confs} {utxo['address']}"
    return s

@tx.group(invoke_without_command=True)
@click.option('-a', '--show-all', '--all', is_flag=True)
@click.option('-u', '--show-unused', '--unused', is_flag=True)
@with_login
@click.pass_context
def inputs(ctx, session, show_all, show_unused):
    """Show and modify transaction inputs.

    With no subcommand shows a summary of the current transaction inputs."""
    if ctx.invoked_subcommand:
        return

    tx = _load_tx(allow_errors=True)

    if show_all or not show_unused:
        for utxo in tx['used_utxos']:
            click.echo(f"{format_utxo(utxo)}")

    if show_all or show_unused:
        for asset, utxos in tx['utxos'].items():
            for utxo in utxos:
                if not _filter_utxos(f"{utxo['txhash']}:{utxo['pt_idx']}", tx['used_utxos']):
                    click.secho(f"{format_utxo(utxo)}", fg='red')

@inputs.command()
@with_login
def auto(session):
    """Enable automatic coin selection.

    Disregards any previous manual selections and reverts to automatic (default) selection.
    """
    with Tx(allow_errors=True) as tx:
        tx['utxo_strategy'] = 'default'

@inputs.command()
@click.argument('utxo_filter')
@with_login
def add(session, utxo_filter):
    """Add transaction inputs."""
    with Tx(allow_errors=True) as tx:
        tx['utxo_strategy'] = 'manual'
        filtered = []
        for asset in tx['utxos']:
            filtered.extend(_filter_utxos(utxo_filter, tx['utxos'][asset]))
            print(f"filtered: {len(filtered)}")
        if not filtered:
            raise click.ClickException(f"No inputs match {utxo_filter}")
        to_add = [utxo for utxo in filtered if not _filter_utxos(f"{utxo['txhash']}:{utxo['pt_idx']}", tx['used_utxos'])]
        print(f"to_add: {len(to_add)}")
        if not to_add:
            raise click.ClickException("Inputs already selected")
        print(f"used_utxos: {len(tx['used_utxos'])}")
        tx['used_utxos'].extend(to_add)
        print(f"used_utxos: {len(tx['used_utxos'])}")

@inputs.command()
@click.argument('utxo_filter')
@with_login
def rm(session, utxo_filter):
    """Remove transaction inputs."""
    with Tx(allow_errors=True) as tx:
        tx['utxo_strategy'] = 'manual'
        filtered = _filter_utxos(utxo_filter, tx['used_utxos'])
        if not filtered:
            raise click.ClickException(f"No selected inputs match {utxo_filter}")
        for utxo in filtered:
            tx['used_utxos'].remove(utxo)

@inputs.command()
@with_login
def clear(session):
    """Remove all transaction inputs."""
    with Tx(allow_errors=True) as tx:
        tx['utxo_strategy'] = 'manual'
        tx['used_utxos'] = []

@tx.command()
@with_login
def sign(session):
    """Sign the current transaction."""
    with Tx(allow_errors=False, recreate=False) as tx:
        signed = gdk_resolve(gdk.sign_transaction(session.session_obj, json.dumps(tx)))
        tx.clear()
        tx.update(signed)

@tx.command()
@with_login
def send(session):
    """Send/broadcast the current transaction."""
    with Tx(allow_errors=False, recreate=False) as tx:
        sent = gdk_resolve(gdk.send_transaction(session.session_obj, json.dumps(tx)))
        tx.clear()
        tx.update(sent)
        click.echo(f"{tx['txhash']}")
