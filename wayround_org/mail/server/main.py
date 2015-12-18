#!/usr/bin/python3

import sys

del sys.path[0]

import logging

import wayround_org.utils.program

wayround_org.utils.program.logging_setup(loglevel='INFO')

import wayround_org.mail.server.commands

commands = wayround_org.mail.server.commands.commands()

ret = wayround_org.utils.program.program('wroms', commands, None)

exit(ret)
