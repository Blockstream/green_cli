from setuptools import setup

setup(
    name='green_cli',
    version=open('green_cli/__init__.py').read().split()[-1].strip("'"),
    description='Blockstream Green Command Line Interface',
    long_description='green-cli is a command line interface to Blockstream Green multisig and singlesig Bitcoin and Liquid wallets, based on the Green gdk library.',
    url='https://github.com/Blockstream/green_cli',
    author='Blockstream',
    author_email='inquiries@blockstream.com',
    license='MIT',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Topic :: Software Development',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
    ],
    keywords=[
        'Blockstream',
        'Green',
        'Bitcoin',
        'wallet',
        'Liquid',
        'Elements',
        'BTC'
    ],
    project_urls={
        'Documentation': 'https://github.com/Blockstream/green_cli/README.md',
        'Source': 'https://github.com/Blockstream/green_cli',
        'Tracker': 'https://github.com/Blockstream/green_cli/issues',
    },
    packages=[
        'green_cli',
        'green_cli/authenticators',
    ],
    install_requires=[
        'wallycore>=1.4.0',
        'green_gdk>=0.75.0',
        'click>=8.1.7',
        'click-repl>=0.3.0',
    ],
    entry_points='''
        [console_scripts]
        green-cli=green_cli.green_cli:main
    ''',
    extras_require={
        'jade': [
            'jade_client>=1.0.32',
        ],
    }
)
