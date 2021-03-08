#!/usr/bin/env python3

import logging
import os
import time
import socket
import json

import gevent
from gevent import socket
from gevent.server import StreamServer

from contestro import config, mkdir, Address
from contestro.io import Server, rpc_method
from contestro.log import root_logger, shell_handler, FileHandler, \
    DetailedFormatter


logger = logging.getLogger(__name__)


class ContestServer(Server):
    def __init__(self, shard):
        Server.__init__(self, shard, config.contest_listen_address,
                        config.contest_listen_port)

        # Import contest datapack

    def _pub_connection_handler(self, sock, address):
        try:
            ipaddr, port = address
            ipaddr = gevent.socket.gethostbyname(ipaddr)
            address = Address(ipaddr, port)
        except OSError:
            logger.warning("Unexpected error.", exc_info=True)
            return

        # Authentication
