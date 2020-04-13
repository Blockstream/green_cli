from green_cli.green import main, with_login, print_result
import green_cli.green as basecli
import click

params = {p.name: p for p in basecli.green.params}
params['network'].type = click.Choice(['liquid', 'localtest-liquid'])
params['network'].help = None
params['network'].default = 'localtest-liquid'

# Add --asset option to sendtoaddress
basecli.sendtoaddress = click.option('--asset', default=None)(basecli.sendtoaddress)
@with_login
@print_result
def sendtoaddress(session, address, amount, details, asset):
    basecli._prepare_send_json(session, address, amount, details)
    if asset is not None:
        details['addressees'][0]['asset_tag'] = asset
    return basecli._send_transaction(session, details)
basecli.sendtoaddress.callback = sendtoaddress

if __name__ == "__main__":
    main()
