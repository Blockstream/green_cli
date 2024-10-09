from setuptools import setup
import green_cli

setup(
    name='green_cli',
    version=green_cli.version,
    description='Blockstream Green Command Line Interface',
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
        'wallycore>=1.3.1',
        'green_gdk>=0.73.2,<0.74.0',
        'click>=8.1.7',
        'click-repl>=0.3.0',
    ],
    entry_points='''
        [console_scripts]
        green-cli=green_cli.green_cli:main
    ''',
)
