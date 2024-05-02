import click
import collections
import functools
import json
import logging

import green_gdk as gdk

from green_cli import context
from green_cli.gdk_resolve import gdk_resolve
from green_cli.notifications import notifications

def format_output(value):
    """Return pretty string representation of value suitable for displaying

    Typically value is a Dict in which case it is pretty printed
    """
    indent, separators = (None, (',', ':')) if context.compact else (2, None)
    # The strip('"') here is for non-json str outputs, for example getnewaddress, which would
    # otherwise be formatted by json.dumps with enclosing double quotes
    return json.dumps(value, indent=indent, separators=separators).strip('"')

def print_result(fn):
    """Print the result of a function to the console

    Decorator to attach to functions that return some value to display to the user
    """
    @functools.wraps(fn)
    def inner(*args, **kwargs):
        click.echo(format_output(fn(*args, **kwargs)))
    return inner

def with_gdk_resolve(fn):
    """Resolve the result of a function call as a GA_auth_handler"""
    @functools.wraps(fn)
    def inner(*args, **kwargs):
        result = fn(*args, **kwargs)
        return gdk_resolve(result)
    return inner

def with_session(fn):
    """Pass a session to a function"""
    @functools.wraps(fn)
    def inner(*args, **kwargs):
        return fn(context.session, *args, **kwargs)
    return inner

def no_warn_sysmsg(fn):
    """Suppress system message warnings on login"""
    @functools.wraps(fn)
    def inner(*args, **kwargs):
        context.no_warn_sysmsg = True
        return fn(*args, **kwargs)
    return inner

def with_login(fn):
    """Pass a logged in session to a function"""
    @functools.wraps(fn)
    def inner(session, *args, **kwargs):
        if not context.logged_in:
            logging.info("Logging in")
            result = context.authenticator.login(session.session_obj)
            context.logged_in = True

            if not context.no_warn_sysmsg:
                # Show the user a prompt to read and acknowledge outstanding system messages
                system_message = gdk.get_system_message(session.session_obj)
                if system_message:
                    click.echo("You have unread system messages, please call getsystemmessages")

        return fn(session, *args, **kwargs)
    return with_session(inner)

def details_json(ctx, param, value):
    """Add an option/parameter to details json

    For many commands options translate directly into elements in a json 'details' input parameter
    to the gdk method. Adding this method as a click.argument callback appends a details json to
    make this convenient.
    """
    if value is not None:
        details = ctx.params.setdefault('details', collections.OrderedDict())
        # hyphens are idiomatic for command line args, so allow some_option to be passed as
        # some-option
        name = param.name.replace("-", "_")
        details[name] = value
    return value

def confs_str(txn_block_height):
    current_block_height = context.session.current_block_height
    if current_block_height is None:
        # Not yet received block notification, current block height unknown
        return '?'
    else:
        if txn_block_height == 0:
            return 'unconfirmed'
        else:
            confs = current_block_height - txn_block_height + 1
            trailer = 'confs' if confs > 1 else 'conf'
            return f'{confs} {trailer}'
