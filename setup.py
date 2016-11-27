#!/usr/bin/python3

from setuptools import setup

setup(
    name='wayround_i2p_mail',
    version='0.0.3',
    description='imap and smtp protocol client and server realisations. under development',
    author='Alexey Gorshkov',
    author_email='animus@wayround.org',
    url='https://github.com/AnimusPEXUS/wayround_i2p_carafe',
    install_requires=[
        'wayround_i2p_utils',
        'wayround_i2p_http'
        ],
    packages=[
        'wayround_i2p.mail'
        ],
    classifiers=[
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)'
        ]
    )
