#!/usr/bin/env python3

import errno
import logging
import os
import socket
import time
import signal
from weakref import WeakSet

import gevent
import gevent.event
import gevent.socket
from gevent.server import StreamServer

from contestro import ConfigError, config, ServiceCoord, Address, \
    get_service_address, mkdir
from .rpc import RemoteServiceServer, RemoteServiceClient, rpc_method, \
    RPCError
from .public_rpc import PublicRemoteServiceServer, PublicRemoteServiceClient, \
    public_rpc_method
from contestro.log import root_logger, shell_handler, ServiceFilter, \
    DetailedFormatter, LogServiceHandler, FileHandler


logger = logging.getLogger(__name__)


class Server:
    '''A service that acts as a server.
    '''
    def __init__(self, shard, server_ip='localhost', server_port=8888):
        signal.signal(signal.SIGINT, lambda unused_x, unused_y: self.exit())

        self.name = self.__class__.__name__
        self.shard = shard
        self._my_coord = ServiceCoord(self.name, self.shard)

        self.remote_services = {}

        # All public connections will be stored for future usage
        self.pub_connections = {}

        try:
            address = get_service_address(self._my_coord)
        except KeyError:
            raise ConfigError('Service %r is not specified in core_services in'
                              'contestro.conf.' % (self._my_coord,))

        self.init_logging()

        # RPC server
        self.rpc_server = StreamServer(address, self._connection_handler)

        # Public server
        # Public server will set to start mode only, while the RPC serve will
        # keep the serve_forever method.
        self._pub_address = Address(server_ip, server_port)
        self.pub_server = StreamServer(self._pub_address,
                                       self._pub_connection_handler)

    def init_logging(self):
        filter_ = ServiceFilter(self.name, self.shard)

        shell_handler.addFilter(filter_)

        log_dir = os.path.join(config.log_dir,
                               '%s-%d' % (self.name, self.shard))

        mkdir(config.log_dir)
        mkdir(log_dir)

        log_filename = time.strftime("%Y-%m-%d-%H-%M-%S.log")

        file_handler = FileHandler(os.path.join(log_dir, log_filename),
                                   mode='w', encoding='utf-8')

        file_log_level = logging.DEBUG if config.log_level_debug else \
            logging.INFO

        file_handler.setLevel(file_log_level)
        file_handler.setFormatter(DetailedFormatter(False))
        file_handler.addFilter(filter_)
        root_logger.addHandler(file_handler)

        try:
            os.remove(os.path.join(log_dir, "last.log"))
        except OSError:
            pass
        os.symlink(log_filename, os.path.join(log_dir, "last.log"))

        if self.name != "LogService":
            log_service = self.connect_to(ServiceCoord("LogService", 0))
            remote_handler = LogServiceHandler(log_service)
            remote_handler.setLevel(logging.INFO)
            remote_handler.addFilter(filter_)
            root_logger.addHandler(remote_handler)

    def connect_to(self, coord, on_connect=None, on_disconnect=None):
        if coord not in self.remote_services:
            try:
                service = RemoteServiceClient(coord, auto_retry=0.5)
            except KeyError:
                raise ConfigError("Missing address and port for %s "
                                  "in cms.conf." % (coord, ))

            service.connect()
            self.remote_services[coord] = service
        else:
            service = self.remote_services[coord]

        if on_connect is not None:
            service.add_on_connect_handler(on_connect)

        if on_disconnect is not None:
            service.add_on_disconnect_handler(on_disconnect)

        return service

    def _connection_handler(self, sock, address):
        try:
            ipaddr, port = address
            ipaddr = gevent.socket.gethostbyname(ipaddr)
            address = Address(ipaddr, port)
        except OSError:
            logger.warning("Unexpected error.", exc_info=True)
            return
        remote_service = RemoteServiceServer(self, address)
        remote_service.handle(sock)

    def _pub_connection_handler(self, sock, address):
        raise NotImplementedError

    def exit(self):
        logger.warning('%r received request to shut down.', self._my_coord)
        self.rpc_server.stop()
        self.pub_server.stop()

    def run(self):
        try:
            self.rpc_server.start()
            self.pub_server.start()
        except socket.gaierror:
            logger.critical('Service %s could not listen on '
                            'specified address, because it cannot '
                            'be resolved.', self.name)
            return False
        except OSError as error:
            if error.errno == errno.EADDRINUSE:
                logger.critical('Listen pot %s for service %s is '
                                'already in use, quitting.',
                                self.rpc_server.address.port, self.name)
                return False
            elif error.errno == errno.EADDRNOTAVAIL:
                logger.critical('Service %s could not listen on '
                                'specified address because it is not '
                                'avaiable.', self.name)
                return False
            else:
                raise

        logger.info('%s %d up and running!', *self._my_coord)

        # Set the RPC server prior to max, only stop when the process is
        # killed or terminated.
        self.rpc_server.serve_forever()

        logger.info('%s %d is shutting down', *self._my_coord)

        self._disconnect_all()
        return True

    def _disconnect_all(self):
        for service in self.remote_services.values():
            if service.connected:
                service.disconnect()

    @rpc_method
    def echo(self, string):
        return string

    @rpc_method
    def quit(self, reason=''):
        logger.info('Trying to exit as asked by another service (%s).', reason)
        self.exit()
