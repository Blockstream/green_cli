from setuptools import setup

setup(
    name='green_cli',
    version='0.1',
    packages=[
        'green_cli'
    ],
    install_requires=[
        'Click',
        'click-repl',
        'greenaddress',
        'hwi',
    ],
    entry_points='''
        [console_scripts]
        green-cli=green_cli.green:green
    ''',
)
