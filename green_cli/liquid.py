"""Modifies base green_cli with liquid specific changes."""
import functools
import string

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

# Restrict networks to liquid networks and default to localtest-liquid
params = {p.name: p for p in green.params}
params['network'].type = click.Choice(['liquid', 'localtest-liquid'])
params['network'].help = None
params['network'].default = 'localtest-liquid'

# Add 2of2_no_recovery as a subaccount type to createsubaccount
params = {p.name: p for p in green_cli.common.createsubaccount.params}
params['type'].type.choices.append('2of2_no_recovery')

@functools.lru_cache(maxsize=None)
def _get_assets(session):
    return context.session.refresh_assets({'assets': True})

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
def _get_assets_by_name(session):
    """Get asset registry indexed by name."""
    assets = _get_assets(session)['assets']
    # Don't return assets with duplicate names or whose names
    # can be mistaken for asset ids
    counts = {}
    for k, v in assets.items():
        if len(v['name']) != 64 or any(c not in string.hexdigits for c in v['name']):
            counts.setdefault(v['name'], list()).append(None)
    return { v['name']: v for k, v in assets.items()
             if v['name'] in counts and len(counts[v['name']]) == 1 }

@functools.lru_cache(maxsize=None)
def _asset_name(asset_id):
    """Get the name of an asset."""
    asset_info = context.session.refresh_assets({'assets': True})
    return asset_info['assets'].get(asset_id, {'name': asset_id})['name']

class Asset(click.ParamType):
    name = 'asset'

    def convert(self, value, param, ctx):
        assert 'asset_id' not in ctx.params['details']['addressees'][-1]
        # Map any (unique) registered asset name to its asset_id
        value = _get_assets_by_name(context.session).get(value, {'asset_id': value})['asset_id']
        ctx.params['details']['addressees'][-1]['asset_id'] = value
        return value

# Add asset parameter to sendtoaddress but also check for unsafe usage
@green.command()
@click.argument('address', type=Address(), expose_value=False)
@click.argument('asset', type=Asset(), expose_value=False)
@click.argument('amount', type=Amount(precision=8), expose_value=False)
@click.option('--subaccount', default=0, expose_value=False, callback=details_json)
@with_login
@print_result
def sendtoaddress(session, details):
    assets = set([a['asset_id'] for a in details['addressees']])
    btc = _get_assets_by_name(context.session)['btc']['asset_id']
    precision_risk = _get_network()['mainnet'] and 'send_all' not in details and assets != {btc}

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

if __name__ == "__main__":
    main()
