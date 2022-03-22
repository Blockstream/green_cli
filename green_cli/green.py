import importlib
import logging
import json
import os

import click

import greenaddress as gdk

from green_cli import context

def _get_config_dir(options):
    """Return the default config dir for network"""
    return os.path.expanduser(os.path.join('~', '.green-cli', options['network']))

def _normalise_auth_config(options):
    """Load additional config json file for the authenticator if required."""
    auth_config = options['auth_config']
    if auth_config is None:
        auth_config = {}
    elif os.path.exists(auth_config):
        with open(auth_config, 'r') as f:
          auth_config = json.load(f)
    else:
        auth_config = json.loads(auth_config)

    options['auth_config'] = auth_config

def _get_authenticator(options):
    """Return an object that implements the authentication interface"""
    auth_module = importlib.import_module('green_cli.authenticators.{}'.format(options['auth']))
    logging.debug("using auth module {}".format(auth_module))
    return auth_module.get_authenticator(options)

@click.group()
@click.option('--log-level', type=click.Choice(['error', 'warn', 'info', 'debug']))
@click.option('--gdk-log', default='none', type=click.Choice(['none', 'debug', 'warn', 'info', 'error']))
@click.option('--network', default='localtest', help='Network: localtest|testnet|mainnet.')
@click.option('--auth', default='default', type=click.Choice(['default', 'hardware', 'wally', 'watchonly']))
@click.option('--auth-config', default=None, help='Additional json config passed to the authenticator')
@click.option('--config-dir', '-C', default=None, help='Override config directory.')
@click.option('--compact', '-c', is_flag=True, help='Compact json output (no pretty printing)')
@click.option('--electrum-url', default=None, type=str, help='Use the given Electrum server')
@click.option('--electrum-tls', default=None, type=bool, help='Connect to Electrum using TLS')
@click.option('--watch-only', is_flag=True, help='Use watch-only login')
@click.option('--spv', is_flag=True, help='Enable SPV verification')
@click.option('--tor', is_flag=True, help='Use tor for external connections')
@click.option('--no-warn-sysmsg', is_flag=True, help='Suppress warning about unread system messages')
@click.option('--expert', is_flag=True, hidden=True)
@click.option('--cert-expiry-threshold', type=int, hidden=True)
def green(**options):
    """Command line interface for Blockstream Green."""
    if context.configured:
        # In repl mode run configuration once only
        return

    if options['log_level']:
        py_log_level = {
            'error': logging.ERROR,
            'warn': logging.WARNING,
            'info': logging.INFO,
            'debug': logging.DEBUG,
        }[options['log_level']]

        logging.basicConfig(level=py_log_level)

    if options['config_dir'] is None:
        options['config_dir'] = _get_config_dir(options)
    os.makedirs(options['config_dir'], exist_ok=True)

    gdk.init({'log_level': options['gdk_log']})

    if options['watch_only']:
        options['auth'] = 'watchonly'

    # Load additional config json file for the authenticator if required
    _normalise_auth_config(options)

    authenticator = _get_authenticator(options)
    context.configure(authenticator, options)
