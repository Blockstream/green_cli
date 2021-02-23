from setuptools import setup
import green_cli

setup(
    name='green_cli',
    version=green_cli.version,
    packages=[
        'green_cli',
        'green_cli/authenticators',
    ],
    install_requires=[
        'Click',
        'click-repl',
        'greenaddress',
    ],
    entry_points='''
        [console_scripts]
        green-cli=green_cli.btc:main
        green-liquid-cli=green_cli.liquid:main
    ''',
)
