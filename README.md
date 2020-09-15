# GreenAddress command line interface

## Installation

It's recommended that you first create and activate a (python3) virtualenv.

1) Install requirements
```
$ pip install -r requirements.txt
```

2) Install green_cli
```
$ pip install .
```

3) [Optional] Enable bash completion
```
$ eval "$(_GREEN_CLI_COMPLETE=source green-cli)"
$ eval "$(_GREEN_LIQUID_CLI_COMPLETE=source green-liquid-cli)"
```

Example usage (testnet):
```
$ green-cli --network testnet set mnemonic -f /file/containing/testnet/mnemonics
$ green-cli --network testnet getbalance
```

For now wallet creation is disabled on use on mainnet/liquid mainnet
