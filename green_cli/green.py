import importlib
import logging
import os

import click

import greenaddress as gdk

from . import context

def _get_config_dir(options):
    """Return the default config dir for network"""
    return os.path.expanduser(os.path.join('~', '.green-cli', options['network']))

def _get_authenticator(options):
    """Return an object that implements the authentication interface"""
    auth_module = importlib.import_module('green_cli.authenticators.{}'.format(options['auth']))
    logging.debug("using auth module {}".format(auth_module))
    return auth_module.get_authenticator(options['network'], options['config_dir'])

@click.group()
@click.option('--log-level', type=click.Choice(['error', 'warning', 'info', 'debug']))
@click.option('--gdk-log', default='none', type=click.Choice(['none', 'debug', 'warn', 'info', 'fatal']))
@click.option('--network', default='localtest', help='Network: localtest|testnet|mainnet.')
@click.option('--auth', default='default', type=click.Choice(['default', 'hardware', 'wally', 'watchonly']))
@click.option('--config-dir', '-C', default=None, help='Override config directory.')
@click.option('--compact', '-c', is_flag=True, help='Compact json output (no pretty printing)')
@click.option('--watch-only', is_flag=True, help='Use watch-only login')
@click.option('--tor', is_flag=True, help='Use tor for external connections')
@click.option('--no-warn-sysmsg', is_flag=True, help='Suppress warning about unread system messages')
@click.option('--expert', is_flag=True, hidden=True)
def green(**options):
    """Command line interface for green gdk"""

    if options['log_level']:
        py_log_level = {
            'error': logging.ERROR,
            'warning': logging.WARNING,
            'info': logging.INFO,
            'debug': logging.DEBUG,
        }[options['log_level']]

        logging.basicConfig(level=py_log_level)

    if options['config_dir'] is None:
        options['config_dir'] = _get_config_dir(options)
    os.makedirs(options['config_dir'], exist_ok=True)

    gdk.init({})

    if options['watch_only']:
        options['auth'] = 'watchonly'

    authenticator = _get_authenticator(options)
    context.configure(authenticator, options)

