import click

class Address(click.ParamType):
    name = 'address'

    def convert(self, value, param, ctx):
        # Append a new addressee dict to addressees
        # Assumes that an address field is always the first in a tuple of addressee fields
        ctx.params.setdefault("details", {})
        ctx.params['details'].setdefault("addressees", [])
        ctx.params['details']['addressees'].append({'address': value})
        return value

class Amount(click.ParamType):
    name = 'amount'

    def __init__(self, precision=0):
        self.precision = precision

    def value2sat(self, value):
        """Takes a decimal string and returns an integer number of satoshis as per precision
        """
        integer_part, _, fractional_part = value.partition('.')
        if len(fractional_part) > self.precision:
            raise click.ClickException("Invalid amount (too many decimal digits)")
        value = (integer_part + f"{fractional_part:0<{self.precision}}").lstrip('0')
        return int(value)

    def convert(self, value, param, ctx):
        assert 'amount' not in ctx.params['details']['addressees'][-1]
        if value == 'all':
            # "all" indicates a greedy output
            ctx.params['details']['addressees'][-1]['is_greedy'] = True
            value = 0
        else:
            value = self.value2sat(value)

        ctx.params['details']['addressees'][-1]['satoshi'] = value
        return value

class UtxoUserStatus(click.ParamType):
    name = 'utxostatus'

    def convert(self, value, param, ctx):
        # Append a new UTXO status to the list of UTXOs to update
        # UTXO status is passed as txhash:pt_idx:status
        ctx.params.setdefault("details", {})
        ctx.params['details'].setdefault("list", [])
        txhash, pt_idx, status = value.split(':')
        ctx.params['details']['list'].append({'txhash': txhash, 'pt_idx': int(pt_idx), 'user_status': status})
        return value
