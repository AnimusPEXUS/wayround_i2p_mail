#!/usr/bin/python3

import sys

del sys.path[0]

import wayround_i2p.utils.socket

wayround_i2p.utils.socket.DEBUG_NB_FUNCS = True


import logging

import wayround_i2p.utils.program

wayround_i2p.utils.program.logging_setup(loglevel='INFO')

import wayround_i2p.mail.server.commands

commands = wayround_i2p.mail.server.commands.commands()

ret = wayround_i2p.utils.program.program('wroms', commands, None)

exit(ret)
