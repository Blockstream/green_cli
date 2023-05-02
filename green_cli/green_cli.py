import click

# This shim dispatches to either the `btc` or `liquid` modules
# depending on the `--network` option.
@click.command(context_settings=dict(ignore_unknown_options=True, allow_extra_args=True), add_help_option=False)
@click.option('--network', default='localtest', help='Network: localtest|testnet|mainnet|localtest-liquid|testnet-liquid|liquid')
def green_cli(*args, **kwargs):
    if 'liquid' in kwargs['network']:
        from green_cli import liquid as cli
    else:
        from green_cli import btc as cli

    cli.main()

def main():
    green_cli()
