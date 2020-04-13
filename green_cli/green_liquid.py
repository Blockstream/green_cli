"""Modifies base green_cli with liquid specific changes.
"""
from green_cli.green import main, with_login, print_result
import green_cli.green as basecli
import click

# Restrict networks to liquid networks and default to localtest-liquid
params = {p.name: p for p in basecli.green.params}
params['network'].type = click.Choice(['liquid', 'localtest-liquid'])
params['network'].help = None
params['network'].default = 'localtest-liquid'

if __name__ == "__main__":
    main()
