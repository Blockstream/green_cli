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

# Hardware wallet support (via hwi) [BETA]

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
