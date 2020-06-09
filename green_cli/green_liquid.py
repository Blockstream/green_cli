"""Modifies base green_cli with liquid specific changes.
"""
from green_cli.green import main, green, with_login, print_result, details_json
from green_cli.liquid_authenticator import WallyAuthenticatorLiquid
import green_cli.green as basecli
import click

# Restrict networks to liquid networks and default to localtest-liquid
params = {p.name: p for p in basecli.green.params}
params['network'].type = click.Choice(['liquid', 'localtest-liquid'])
params['network'].help = None
params['network'].default = 'localtest-liquid'

# Add 2of2_no_recovery as a subaccount type to createsubaccount
params = {p.name: p for p in basecli.createsubaccount.params}
params['type'].type.choices.append('2of2_no_recovery')

@green.command()
@click.option('--refresh', is_flag=True, default=False, expose_value=False, callback=details_json)
@click.option('--icons', is_flag=True, default=False, expose_value=False, callback=details_json)
@with_login
@print_result
def getassetinfo(session, details):
    details['assets'] = True
    return session.refresh_assets(details)

basecli.WallyAuthenticator = WallyAuthenticatorLiquid

if __name__ == "__main__":
    main()
