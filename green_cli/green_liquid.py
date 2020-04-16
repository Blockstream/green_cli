from green_cli.green import main, green, with_login, print_result, details_json
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

basecli.sendtoaddress.params.insert(1, click.Argument(('asset',), type=Asset()))
@with_login
@print_result
def sendtoaddress(session, address, asset, amount, details):
    if amount == "all":
        details['send_all'] = True
        amount = 0
    details['addressees'] = [{'address': address, 'asset_tag': asset, 'satoshi': amount}]
    return basecli._send_transaction(session, details)
basecli.sendtoaddress.callback = sendtoaddress

if __name__ == "__main__":
    main()
