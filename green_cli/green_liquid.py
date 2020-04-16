"""Modifies base green_cli with liquid specific changes.
"""
from green_cli.green import main, green, with_login, print_result, details_json
import green_cli.green as basecli
import click

# Restrict networks to liquid networks and default to localtest-liquid
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

if __name__ == "__main__":
    main()
