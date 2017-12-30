"""Setuptools based setup module for mydnshost-python-api."""

from os import path
from setuptools import setup

here = path.abspath(path.dirname(__file__))

setup(
    name='mydnshost',

    version='0.0.1',

    description='Command-line tool to interact with the MyDnsHost.co.uk API',
    long_description='Command-line tool that allows updating of DNS records ' \
                     'via the MyDNSHost API. ',

    url='https://github.com/mydnshost/mydnshost-python-api',

    author='Chris Smith',
    author_email='mdh-api@chameth.com',

    license='MIT',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3 :: Only',
        'Topic :: System :: Systems Administration',
        'Topic :: Utilities',
    ],

    keywords='dns mydnshost',

    py_modules=["api", "cli"],

    install_requires=["requests[security]"],

    entry_points={
        'console_scripts': [
            'mydnshost=cli:main',
        ],
    },
)

