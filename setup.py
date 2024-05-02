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
        'green_gdk',
    ],
    entry_points='''
        [console_scripts]
        green-cli=green_cli.green_cli:main
    ''',
)
