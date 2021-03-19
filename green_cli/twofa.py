import json
import logging

import click

import greenaddress as gdk

from green_cli.green import green
from green_cli.decorators import (
    with_login,
    print_result,
    with_gdk_resolve,
)

@green.group(name="2fa")
def twofa():
    """Two-factor authentication."""

@twofa.command()
@with_login
@print_result
def getconfig(session):
    """Print two-factor authentication configuration."""
    return session.get_twofactor_config()

@twofa.group(name="enable")
def enabletwofa():
    """Enable an authentication factor."""

def _enable_2fa(session, factor, data):
    details = {'confirmed': True, 'enabled': True, 'data': data}
    logging.debug("_enable_2fa factor='{}', details={}".format(factor, details))
    return gdk.change_settings_twofactor(session.session_obj, factor, json.dumps(details))

@enabletwofa.command()
@click.argument('email_address')
@with_login
@with_gdk_resolve
def email(session, email_address):
    """Enable email 2fa."""
    return _enable_2fa(session, 'email', email_address)

@enabletwofa.command()
@click.argument('number')
@with_login
@with_gdk_resolve
def sms(session, number):
    """Enabled SMS 2fa."""
    return _enable_2fa(session, 'sms', number)

@enabletwofa.command()
@click.argument('number')
@with_login
@with_gdk_resolve
def phone(session, number):
    """Enable phone 2fa."""
    return _enable_2fa(session, 'phone', number)

@enabletwofa.command()
@with_login
@with_gdk_resolve
def gauth(session):
    """Enable gauth 2fa."""
    data = session.get_twofactor_config()['gauth']['data']
    key = data.partition('secret=')[2]
    click.echo('Google Authenticator key: {}'.format(key))
    return _enable_2fa(session, 'gauth', data)

@enabletwofa.command()
@with_login
@with_gdk_resolve
def telegram(session):
    """Enable telegram 2fa"""
    config = session.get_twofactor_config()
    if 'telegram' not in config:
        raise click.ClickException("Telegram not available")
    return _enable_2fa(session, 'telegram', '')

@enabletwofa.command()
@with_login
@with_gdk_resolve
def u2f(session):
    """Enable u2f 2fa"""
    return _enable_2fa(session, 'u2f', '')

@twofa.command()
@click.argument('factor', type=click.Choice(['email', 'sms', 'phone', 'gauth', 'telegram', 'u2f']))
@with_login
@with_gdk_resolve
def disable(session, factor):
    """Disable an authentication factor."""
    details = {'confirmed': True, 'enabled': False}
    return gdk.change_settings_twofactor(session.session_obj, factor, json.dumps(details))

@twofa.command()
@click.argument('threshold', type=str)
@click.argument('key', type=str)
@with_login
@with_gdk_resolve
def setthreshold(session, threshold, key):
    """Set the two-factor threshold."""
    is_fiat = key == 'fiat'
    details = {'is_fiat': is_fiat, key: threshold}
    return gdk.twofactor_change_limits(session.session_obj, json.dumps(details))

@twofa.group(name="reset")
def twofa_reset():
    """Two-factor authentication reset."""

@twofa_reset.command()
@click.argument('reset_email')
@with_login
@with_gdk_resolve
def request(session, reset_email):
    """Request a 2fa reset."""
    is_dispute = False
    return gdk.twofactor_reset(session.session_obj, reset_email, is_dispute)

@twofa_reset.command()
@click.argument('reset_email')
@with_login
@with_gdk_resolve
def dispute(session, reset_email):
    """Dispute a 2fa reset."""
    is_dispute = True
    return gdk.twofactor_reset(session.session_obj, reset_email, is_dispute)

@twofa_reset.command()
@click.argument('reset_email')
@with_login
@with_gdk_resolve
def undo(session, reset_email):
    """Undo a 2fa reset request."""
    return gdk.twofactor_undo_reset(session.session_obj, reset_email)

@twofa_reset.command()
@with_login
@with_gdk_resolve
def cancel(session):
    """Cancel a 2fa reset."""
    return gdk.twofactor_cancel_reset(session.session_obj)


