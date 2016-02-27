#!/usr/bin/python3

from setuptools import setup

setup(
    name='wayround_org_mail',
    version='0.0.1',
    description='imap and smtp protocol client and server realisations. under development',
    author='Alexey Gorshkov',
    author_email='animus@wayround.org',
    url='https://github.com/AnimusPEXUS/wayround_org_carafe',
    install_requires=[
        'wayround_org_utils',
        'wayround_org_http'
        ],
    packages=[
        'wayround_org.mail'
        ],
    classifiers=[
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)'
        ]
    )
