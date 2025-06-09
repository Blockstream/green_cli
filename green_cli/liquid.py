"""Modifies base green_cli with liquid specific changes."""
import functools
import string
from collections import defaultdict

import click

import green_gdk as gdk

from green_cli import context
from green_cli.green import green
from green_cli.decorators import (
    details_json,
    with_login,
    print_result,
    with_gdk_resolve,
)
from green_cli.common import (
    main,
    _get_network,
)
from green_cli.param_types import (
    Address,
    Amount,
)

import green_cli.twofa
import green_cli.tx

def _get_liquid_networks():
    def is_liquid(network):
        return 'liquid' in network
    return list(reversed([n for n in gdk.get_networks() if is_liquid(n)]))

# Restrict networks to liquid networks and default to localtest-liquid
params = {p.name: p for p in green.params}
params['network'].type = click.Choice(_get_liquid_networks())
params['network'].help = None
params['network'].default = 'localtest-liquid'

# Add 2of2_no_recovery as a subaccount type to createsubaccount
params = {p.name: p for p in green_cli.common.createsubaccount.params}
params['type'].type.choices.append('2of2_no_recovery')

@functools.lru_cache(maxsize=None)
def _get_assets(session):
    return context.session.get_assets({'category': 'all'})

# Add getassetinfo command
@green.command()
@with_login
@print_result
@click.option('--refresh', is_flag=True, default=False, expose_value=False, callback=details_json)
@click.option('--icons', is_flag=True, default=False, expose_value=False, callback=details_json)
def getassetinfo(session, details):
    if details['refresh']:
        session.refresh_assets({'assets': True, 'icons': details['icons']})
    return session.get_assets({'category': 'all'})

# Add validateassetdomainname command
@green.command()
@click.option('--asset-id', expose_value=False, callback=details_json)
@click.option('--domain', expose_value=False, callback=details_json)
@with_login
@print_result
def validateassetdomainname(session, details):
    return session.validate_asset_domain_name(details)

@functools.lru_cache(maxsize=None)
def _get_assets_by_name(session):
    """Get asset registry indexed by name."""
    assets = _get_assets(session)['assets']
    # Don't return assets with duplicate names or whose names
    # can be mistaken for asset ids
    counts = {}
    for k, v in assets.items():
        if len(v['name']) != 64 or any(c not in string.hexdigits for c in v['name']):
            counts.setdefault(v['name'], list()).append(None)
    return {v['name']: v for k, v in assets.items()
            if v['name'] in counts and len(counts[v['name']]) == 1}

@functools.lru_cache(maxsize=None)
def _asset_name(asset_id):
    """Get the name of an asset."""
    asset_info = context.session.get_assets({'assets_id': [asset_id]})
    return asset_info['assets'].get(asset_id, {'name': asset_id})['name']

class Asset(click.ParamType):
    name = 'asset'

    def convert(self, value, param, ctx):
        assert 'asset_id' not in ctx.params['details']['addressees'][-1]
        if not _get_network()['mainnet']:
            # Map any (unique) registered asset name to its asset_id.
            # This is disabled in mainnet since the asset registry has
            # no constraints on the data entered and so assets can trivially
            # be spoofed by name or ticker.
            default = {'asset_id': value}
            value = _get_assets_by_name(context.session).get(value, default)['asset_id']
        ctx.params['details']['addressees'][-1]['asset_id'] = value
        return value

def format_utxo(utxo):
    confs = green_cli.tx.confs_str(utxo['block_height'])
    s = f"{utxo['satoshi']} {_asset_name(utxo['asset_id'])}"
    s += f" {utxo['txhash']}:{utxo['pt_idx']} {utxo['address_type']} {confs} {utxo['address']}"
    return s

green_cli.tx.format_utxo = format_utxo

# Add asset parameter to tx.outputs.add
asset_arg = click.Argument(['asset'], type=Asset(), expose_value=False)
green_cli.tx.add_outputs.params.insert(1, asset_arg)

# Add asset parameter to sendtoaddress but also check for unsafe usage
@green.command()
@with_login
@print_result
@click.argument('address', type=Address(), expose_value=False)
@click.argument('asset', type=Asset(), expose_value=False)
@click.argument('amount', type=Amount(precision=8), expose_value=False)
@click.option('--subaccount', default=0, expose_value=False, callback=details_json)
@click.option('--timeout', default=0, type=int, help='Maximum number of seconds to wait')
def sendtoaddress(session, details, timeout):
    assets = set([a['asset_id'] for a in details['addressees']])
    btc = _get_assets_by_name(context.session)['btc']['asset_id']
    precision_risk = _get_network()['mainnet'] and assets != {btc}

    if precision_risk and not context.expert:
        # Disable sendtoaddress for non btc assets on mainnet
        # The interface is considered unsafe due to the ambiguity of the amount field. For btc the
        # amount passed to sendtoaddress is interpreted as btc (satoshi x10^8), however assets may
        # have different 'precision' specified and it's not currently clear how best to handle that.
        # Leave functionality on for testnet/dev environments as it is convenient
        raise click.ClickException("Unsafe asset amount conversion disabled")
    return green_cli.common._send_transaction(session, details, timeout)

# Insert asset into addressee option for createtransaction
params = {p.name: p for p in green_cli.common.createtransaction.params}
params['addressee'].type = click.Tuple((Address(), Asset(), Amount()))
params['addressee'].nargs = 3

# Add '--confidential' option to getbalance and getunspentoutputs
confidential_option = click.Option(
    ['--confidential'], is_flag=True, expose_value=False, callback=details_json,
    help='Include only confidential utxos')
green_cli.common.getbalance.params.append(confidential_option)
green_cli.common.getunspentoutputs.params.append(confidential_option)

def _print_tx_summary(tx):
    click.echo(f"utxo strategy: {tx.get('utxo_strategy', 'default')}")

    available_per_asset = defaultdict(int)
    used_per_asset = defaultdict(int)
    change_per_asset = defaultdict(int)
    for asset in tx['utxos']:
        available = sum([utxo['satoshi'] for utxo in tx['utxos'][asset]])
        available_per_asset[_asset_name(asset)] += available
    for tx_input in tx['transaction_inputs']:
        used_per_asset[_asset_name(tx_input['asset_id'])] += tx_input['satoshi']
    for asset in tx.get('change_amount', {}):
        change_per_asset[_asset_name(asset)] += tx['change_amount'][asset]

    for asset in available_per_asset:
        click.echo(f"{asset}:")
        click.echo(f"\tavailable: {available_per_asset[asset]}")
        click.echo(f"\tused: {used_per_asset[asset]}")
        click.echo(f"\tchange: {change_per_asset[asset]}")

    click.echo(f"vsize: {tx.get('transaction_vsize', 0)}")
    click.echo(f"weight: {tx.get('transaction_weight', 0)}")
    click.echo(f"fee: {tx.get('fee', 0)}")
    click.echo(f"fee rate: {tx.get('calculated_fee_rate', 0)} lsat/kb")

green_cli.tx._print_tx_summary = _print_tx_summary

def _print_tx_output(options, output):
    fg = None
    if not output['scriptpubkey']:
        fg = 'red'
        if not options['show_all'] and not options['show_fee']:
            return
    elif output.get('is_change', False):
        fg = 'green'
        if not options['show_all'] and not options['show_change']:
            return
    else:
        if not options['show_all'] and options['show_fee'] or options['show_change']:
            return

    value = output['satoshi']
    asset_name = _asset_name(output['asset_id'])
    dest = output['address'] if output['scriptpubkey'] else 'fee'
    click.secho(f"{value} {asset_name} {dest}", fg=fg, color=context.color())

# Liquid txs have explicit fee outputs
green_cli.tx.outputs.params.append(click.Option(['-f', '--show-fee', '--fee'], is_flag=True))
green_cli.tx._print_tx_output = _print_tx_output

# Default the version option of dumppsbt to 2 for Liquid, since
# PSET does not support v0
green_cli.tx.dumppsbt.params[-1].default = '2'

@green.command()
@with_login
@print_result
@with_gdk_resolve
@click.argument('details', type=click.File('rb'))
def createswaptransaction(session, details):
    """Create a swap proposal from initial 'maker' details json"""
    maker_details = details.read().decode('utf-8')
    return gdk.create_swap_transaction(session.session_obj, maker_details)

@green.command()
@with_login
@print_result
@with_gdk_resolve
@click.argument('details', type=click.File('rb'))
def completeswaptransaction(session, details):
    """Create a complete swap transaction from the 'taker' details"""
    taker_details = details.read().decode('utf-8')
    return gdk.complete_swap_transaction(session.session_obj, taker_details)

if __name__ == "__main__":
    main()
