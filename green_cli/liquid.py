"""Modifies base green_cli with liquid specific changes."""
from collections import defaultdict
import functools

import click

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

# Restrict networks to liquid networks and default to localtest-liquid
params = {p.name: p for p in green.params}
params['network'].type = click.Choice(['liquid', 'localtest-liquid'])
params['network'].help = None
params['network'].default = 'localtest-liquid'

# Add 2of2_no_recovery as a subaccount type to createsubaccount
params = {p.name: p for p in green_cli.common.createsubaccount.params}
params['type'].type.choices.append('2of2_no_recovery')

# Add getassetinfo command
@green.command()
@click.option('--refresh', is_flag=True, default=False, expose_value=False, callback=details_json)
@click.option('--icons', is_flag=True, default=False, expose_value=False, callback=details_json)
@with_login
@print_result
def getassetinfo(session, details):
    details['assets'] = True
    return session.refresh_assets(details)

@functools.lru_cache(maxsize=None)
def _asset_name(asset_id):
    """Get the name of an asset."""
    asset_info = context.session.refresh_assets({'assets': True})
    return asset_info['assets'].get(asset_id, {'name': asset_id})['name']

class Asset(click.ParamType):
    name = 'asset'

    def convert(self, value, param, ctx):
        assert 'asset_tag' not in ctx.params['details']['addressees'][-1]
        ctx.params['details']['addressees'][-1]['asset_tag'] = value
        return value

def format_utxo(utxo):
    confs = green_cli.tx.confs_str(utxo['block_height'])
    s = f"{utxo['satoshi']} {_asset_name(utxo['asset_id'])}"
    s += f" {utxo['txhash']}:{utxo['pt_idx']} {utxo['address_type']} {confs} {utxo['address']}"
    return s

green_cli.tx.format_utxo = format_utxo

# Add asset parameter to tx.outputs.add
asset_arg = click.Argument(['asset',], type=Asset(), expose_value=False)
green_cli.tx.add_outputs.params.insert(1, asset_arg)

# Add asset parameter to sendtoaddress but also check for unsafe usage
@green.command()
@click.argument('address', type=Address(), expose_value=False)
@click.argument('asset', type=Asset(), expose_value=False)
@click.argument('amount', type=Amount(precision=8), expose_value=False)
@click.option('--subaccount', default=0, expose_value=False, callback=details_json)
@with_login
@print_result
def sendtoaddress(session, details):
    assets = set([a['asset_tag'] for a in details['addressees']])
    precision_risk = _get_network()['mainnet'] and 'send_all' not in details and assets != {'btc'}
    if precision_risk and not context.expert:
        # Disable sendtoaddress for non btc assets with amounts on mainnet
        # The interface is considered unsafe due to the ambiguity of the amount field. For btc the
        # amount passed to sendtoaddress is interpreted as btc (satoshi x10^8), however assets may
        # have different 'precision' specified and it's not currently clear how best to handle that.
        # Leave functionality on for testnet/dev environments as it is convenient
        raise click.ClickException("Unsafe asset amount conversion disabled")
    return green_cli.common._send_transaction(session, details)

# Insert asset into addressee option for createtransaction
params = {p.name: p for p in green_cli.common.createtransaction.params}
params['addressee'].type = click.Tuple((Address(), Asset(), Amount()))
params['addressee'].nargs = 3

# Add '--confidential' option to getbalance and getunspentoutputs
confidential_option = click.Option(
    ['--confidential',], is_flag=True, expose_value=False, callback=details_json,
    help='Include only confidential utxos')
green_cli.common.getbalance.params.append(confidential_option)
green_cli.common.getunspentoutputs.params.append(confidential_option)

def _print_tx_summary(tx):
    click.echo(f"user signed: {tx['user_signed']}")
    click.echo(f"server signed: {tx['server_signed']}")
    click.echo(f"send all: {tx.get('send_all', False)}")
    click.echo(f"utxo strategy: {tx['utxo_strategy']}")

    available_per_asset = defaultdict(int)
    used_per_asset = defaultdict(int)
    change_per_asset = defaultdict(int)
    for asset in tx['utxos']:
        available = sum([utxo['satoshi'] for utxo in tx['utxos'][asset]])
        available_per_asset[_asset_name(asset)] += available
    for utxo in tx['used_utxos']:
        used_per_asset[_asset_name(utxo['asset_id'])] += utxo['satoshi']
    for asset in tx['change_amount']:
        change_per_asset[_asset_name(asset)] += tx['change_amount'][asset]

    for asset in available_per_asset:
        click.echo(f"{asset}:")
        click.echo(f"\tavailable: {available_per_asset[asset]}")
        click.echo(f"\tused: {used_per_asset[asset]}")
        click.echo(f"\tchange: {change_per_asset[asset]}")

    click.echo(f"size: {tx['transaction_size']}")
    click.echo(f"vsize: {tx['transaction_vsize']}")
    click.echo(f"weight: {tx['transaction_weight']}")
    click.echo(f"fee: {tx['fee']}")
    click.echo(f"fee rate: {tx['calculated_fee_rate']} sat/kb")

green_cli.tx._print_tx_summary = _print_tx_summary

def _print_tx_output(options, output):
    fg = None
    if output['is_fee']:
        fg = 'red'
        if not options['show_all'] and not options['show_fee']:
            return
    elif output['is_change']:
        fg = 'green'
        if not options['show_all'] and not options['show_change']:
            return
    else:
        if not options['show_all'] and options['show_fee'] or options['show_change']:
            return

    value = output['satoshi']
    asset = _asset_name(output['asset_id'])
    dest = 'fee' if output['is_fee'] else output['address']
    click.secho(f"{value} {asset} {dest}", fg=fg)

# Liquid txs have explicit fee outputs
green_cli.tx.outputs.params.append(click.Option(['-f', '--show-fee', '--fee'], is_flag=True))
green_cli.tx._print_tx_output = _print_tx_output

if __name__ == "__main__":
    main()
