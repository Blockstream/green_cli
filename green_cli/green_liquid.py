from green_cli.green import (
    Address,
    Amount,
    details_json,
    green,
    main,
    print_result,
    with_login,
    )
import green_cli.green as basecli
import click

params = {p.name: p for p in basecli.green.params}
params['network'].type = click.Choice(['liquid', 'localtest-liquid'])
params['network'].help = None
params['network'].default = 'localtest-liquid'

@green.command()
@click.option('--refresh', is_flag=True, default=False, expose_value=False, callback=details_json)
@with_login
@print_result
def getassetinfo(session, details):
    details['assets'] = True
    details['icons'] = False
    return session.refresh_assets(details)

class Asset(click.ParamType):
    name = 'asset'

def _apply_dp(value, dp):
    """Return the number of fractional units from a decimal (i.e. right shift the decimal point)"""
    integers, decimals = value.split('.')
    decimals = decimals[:dp]
    fmt = "{{}}{{:0<{}}}".format(dp)
    return int(fmt.format(integers, decimals).lstrip('0'))

def _match_asset(info, asset):
    for key in 'ticker', 'name':
        if key in info and info[key] == asset:
            return True
    return False

class TransactionOutput(basecli.TransactionOutput):

    def __init__(self):
        click.Tuple.__init__(self, types=(Address(), Asset(), Amount()))

    def get_metavar(self, param):
        return "ADDRESS ASSET AMOUNT"

_tx_output_arg = click.Argument(('output',), type=TransactionOutput())
_dp_option = click.Option(('--amount-dp',), type=int, help='Number of decimal places of amount')
basecli.sendtoaddress.params = [_tx_output_arg, _dp_option] + basecli.sendtoaddress.params[1:]
@with_login
@print_result
def sendtoaddress(session, output, amount_dp, details):
    address, asset, amount = output
    if amount == 'all':
        details['send_all'] = True
        amount = 0

    # Look for the asset in the asset registry data to get the number of decimal places
    # ('precision').
    #
    # The command line interface accepts the amounts in the base unit of the asset, consistent with
    # the btc version of sendtoaddress. The gdk requires the amount in fractional units, and the
    # conversion between them is defined per asset. Caller can overried with the --amount-dp option
    #
    # set refresh=True, this is going to be a bit slower but it's important that the most
    # up to date asset info is used to determine the "precision" (number of decimal places to
    # use when interpreting the value provided by the user)
    refresh_asset_details = {'assets': True, 'icons': False, 'refresh': True}
    assets = basecli.context.session.refresh_assets(refresh_asset_details)['assets']
    registry_dp = None
    found = False
    for tag, info in assets.items():
        if tag == asset or _match_asset(info, asset):
            if found:
                raise click.ClickException("Ambiguous asset")
            found = True
            if 'precision' in info:
                if amount_dp is not None and amount_dp != info['precision']:
                    raise click.ClickException("Cannot override --amount-dp for registered asset")
                amount_dp = info['precision']

    if amount_dp is None:
        raise click.ClickException("Cannot determine asset precision, pass --amount-dp?")

    amount = _apply_dp(amount, amount_dp)
    details['addressees'] = [{'address': address, 'asset_tag': asset, 'satoshi': amount}]
    return basecli._send_transaction(session, details)

basecli.sendtoaddress.callback = sendtoaddress

if __name__ == "__main__":
    main()
