# GreenAddress command line interface

## Installation

It's recommended that you first create and activate a (python3)
virtualenv and use that to install the green-cli.

Note that the package installs two scripts: green-cli for use with the
bitcoin network an green-liquid-cli for the liquid network.

# Basic install

1) Install requirements
```
$ pip install -r requirements.txt
```

2) Install green_cli
```
$ pip install .
```

3) [Optional] Enable bash completion
for green-cli:
```
$ eval "$(_GREEN_CLI_COMPLETE=source green-cli)"
```

for green-liquid-cli:
```
$ eval "$(_GREEN_LIQUID_CLI_COMPLETE=source green-liquid-cli)"
```

# Blockstream Jade hardware wallet support

To enable support for the Blockstream Jade hardware wallet (via
the `--auth jade` option) additional dependencies must be installed
from requirements-wally.txt and requirements-jade.txt.

1) Install libudev and libusb. This is platform specific but for
debian-based systems:
```
$ sudo apt-get install libudev-dev libusb-1.0-0-dev
```

2) Install extra requirements
```
$ pip install -r requirements-wally.txt
$ pip install -r requirements-jade.txt
```
NOTE: this must be two separate invocations, as the jade python api is installed from github sources, and does not have a sha hash.

You can now run green-cli (or green-liquid-cli) passing the `--auth
jade` option.

# Generic hardware wallet support (via hwi) [BETA]

To enable hardware wallet support (via the `--auth hardware` option)
additional dependencies must be installed from requirements-hwi.txt.

1) Install libudev and libusb. This is platform specific but for
debian-based systems:
```
$ sudo apt-get install libudev-dev libusb-1.0-0-dev
```

2) Install extra requirements
```
$ pip install -r requirements-hwi.txt
```

You can now run green-cli (or green-liquid-cli) passing the `--auth
hardware` option.

# Software authenticator support (via libwally) [BETA]

There is another authenticator option `--auth wally` which delegates the
possession of key material (the mnemonic) and authentication services to
python code external to the gdk using the hardware wallet interface.
This is useful for testing and as a demonstration of the technique. In
order to enable this option libwally must be installed:

```
$ pip install -r requirements-wally.txt
```

# Override hww capabilities

If using the options `--auth hardware` or `--auth wally` it is possible to
override the default device capabilities sent to the GDK, using the
`--auth-config` option and the `device` key.

eg:
```
--auth hardware --auth-config '{"device": {"supports_low_r": true}}'
```

Note `--auth-config` json data can also be passed in a text file:
```
--auth wally --auth-config hw_liquid_lowr.json
```
where the file contents are, eg:
```
{
    "device": {
        "supports_low_r": true,
        "supports_liquid": 1
    }
}
```

# Example usage

Log in to a testnet wallet and report the balance:
```
$ green-cli --network testnet set mnemonic -f /file/containing/testnet/mnemonics
$ green-cli --network testnet getbalance
```

Log in to a mainnet wallet and send 0.1 BTC to an address
```
$ green-cli --network mainnet set mnemonic "mainnet mnemonic here ..."
$ green-cli --network mainnet sendtoaddress $ADDR 0.1
```

Log in to a liquid wallet and send an asset to an address
```
$ green-liquid-cli --network liquid set mnemonic "liquid mnemonic here ..."
$ green-liquid-cli --network liquid sendtoaddress
```

For now wallet creation is disabled on use on mainnet/liquid mainnet

## Manual coin selection (alpha - use at your own risk)

WARNING: Please note that green-cli in general and the tx/coin selection
functions in particular are alpha software and not currently recommended
for mainnet use. Loss of funds may occur.

You can create, inspect and modify a transaction using the `tx` command.
Although you can issue individual `tx` commands directly from the shell
it can be easier to use the green-cli's inbuilt repl shell when
interactively building transactions as it avoids the overhead of logging
in to green each time. Use the `repl` command to start a repl session.
ctrl-d exits the session.

```
$ green-cli --network testnet repl
```

### Create a new transaction
First, create a new 'scratch' transaction using the `tx` command
```
> tx new
```

This creates a new temporary local transaction. At any time you can
start again by running `tx new` which will discard the scratch tx and
create a new one.

### Adding outputs
Add an output to the transaction.
```
> tx outputs add mkHS9ne12qx9pS9VojpwU5xtRd4T7X7ZUt 1000
```

Use `tx outputs` to show the current outputs
```
> tx outputs
1000 mkHS9ne12qx9pS9VojpwU5xtRd4T7X7ZUt
```

By default `tx outputs` does not show change outputs. Pass `-a` to show
all outputs, including change, or '-c' to show only change outputs.
Change outputs are shown in green.
```
> tx outputs -a
996380 2N1txpptYbDvCd5RF8jR3ERzRdEWyWVyWZB
1000 mkHS9ne12qx9pS9VojpwU5xtRd4T7X7ZUt

> tx outputs -c
996380 2N1txpptYbDvCd5RF8jR3ERzRdEWyWVyWZB
```

### Transaction summary
At any point you can print a summary of the using the `tx` command.
```
> tx
send all: False
utxo strategy: default
available inputs: 1787590
selected inputs: 997590
total outputs: 1000
change: 996380
size: 381
vsize: 210
weight: 837
fee: 210
fee rate: 1000 sat/kb
```

### Transaction inputs (coin selection)
Note that 'utxo strategy' is 'default', which means the transaction
inputs have been automatically selected. Use `tx inputs` to see the
selected inputs.
```
> tx inputs
997590 86b29eeed79ad3fe977f49c37fd7cc415887b422892ad943187196fec019e5c4:1 csv 1005 confs 2N9aB1hjFrQrauVxDqwugVqtFeQNgHd8ptN
```

Pass `-u` to see available unused inputs, or `-a` to see all inputs,
selected and available. Unselected inputs show in red.
```
> tx inputs -u
660000 bbe2c68e8af9e777988823682f4ecc59ab3c94bcaf42c50aba99016f868f0ebd:0 csv 205 confs 2N1VynvdyXKadB8fWLmmKbEQe46n1YALHmj
30000 c6b84a5ab4fbd6ee963e165aed36bd5a40c7aadede818be79b8445f3992f0031:1 csv 205 confs 2N3cq3JVs7RZrVqpHUnk8VFRsZPV7iYr5qT
100000 0c0863f5ab4e11c6844b25b2883a4056be8f245aa2da09e34b54d8a61b840d26:1 csv 205 confs 2NDky839U4fqR19y6Lz7xLSGEitHjqJvSqA
```

Automatic input selection can be overridden using the `tx inputs`
command. Use `tx inputs clear` to remove all selected inputs.
```
> tx inputs clear
> tx inputs
```

Use `tx inputs add` to add inputs. You can pass either an address, or a
transaction id, or a transaction id + vout. If you pass an address all
utxos for that address will be selected. If you pass a transaction id
without a vout index any utxos from that transaction will be selected.
You can also use '*' as a wildcard.
```
> tx inputs add 86b29eeed79ad3fe977f49c37fd7cc415887b422892ad943187196fec019e5c4
> tx inputs add bbe2c68e8af9e777988823682f4ecc59ab3c94bcaf42c50aba99016f868f0ebd:0
> tx inputs add 2NDky839U4fqR19y6Lz7xLSGEitHjqJvSqA
> tx inputs add *
```

tx inputs and outputs can be cleared using `tx inputs clear` and `tx
outputs clear`, or individually removed using `tx inputs rm` and `tx
outputs rm`

### Sending all outputs with no change
You can add an output which consumes all of the available inputs, less
the fee, by specifying 'all' as the amount. Before doing so, if
necessary either create a new transaction or use `tx outputs clear`.
Once an 'all' output is set the inputs can be manually selected as usual
and the amount paid to the output will automatically adjust such that
there is no change.
```
> tx outputs clear
> tx outputs add mkHS9ne12qx9pS9VojpwU5xtRd4T7X7ZUt all
```

Using `tx outputs -a` shows there are no change outputs, and this
confirmed by the summary.
```
> tx outputs -a
1757147 mkHS9ne12qx9pS9VojpwU5xtRd4T7X7ZUt
> tx
user signed: False
server signed: False
send all: True
utxo strategy: manual
available inputs: 1757590
selected inputs: 1757590
total outputs: 1757147
change: 0
size: 955
vsize: 443
weight: 1771
fee: 443
fee rate: 1000 sat/kb
```

### Changing the fee
You can change the feerate by calling `tx setfeerate`. The fee rate is
specified in satoshis per kilobyte.

### Signing and sending the transaction
When the transaction is ready, use `tx sign` and `tx send`. Before
signing and sending a transaction it is strongly recommended that you
use `tx raw` and inspect the raw transaction, for example by passing it
to `bitcoin-cli decoderawtransaction`, to ensure the details are as
expected.

```
> tx sign
> tx send
d425b376ab69969668011a29638bcf3aad507da3d9adecd4a241cb2b1f6684ba
```
