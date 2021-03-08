#!/usr/bin/env python3

import functools
import json
import logging
import socket
import traceback
import uuid
from weakref import WeakSet

import gevent
import gevent.event
import gevent.lock
import gevent.socket

from contestro import Address
from .rpc import RPCError


logger = logging.getLogger(__name__)


def public_rpc_method(func):
    func.public_rpc_callable = True
    return func


class PublicRemoteServiceBase:
    '''Same class as the RPC Base, but support public connections from the
    defined clients instead of the local services.

    '''
    # This message size is experimental. This will be changed in the future
    # based on the further purpose of the public RPC Server.
    MAX_MESSAGE_SIZE = 1024 * 1024

    def __init__(self, remote_address):
        self._local_address = None
        if isinstance(remote_address, str):
            ip, port = remote_address.split(":")
            self.remote_address = Address(ip, port)
        else:
            self.remote_address = Address(remote_address[0], remote_address[1])
        self._connection_event = gevent.event.Event()

        self._on_connect_handlers = list()
        self._on_disconnect_handlers = list()

        self._socket = None
        self._reader = None
        self._writer = None

        self._read_lock = gevent.lock.RLock()
        self._write_lock = gevent.lock.RLock()

    @property
    def connected(self):
        return self._connection_event.is_set()

    def add_on_connect_handler(self, handler):
        self._on_connect_handlers.append(handler)

    def add_on_disconnect_handler(self, handler):
        self._on_disconnect_handlers.append(handler)

    def _repr_remote(self):
        return "%s:%d" % (self.remote_address)

    def initialize(self, sock, plus):
        if self.connected:
            raise RuntimeError("Already connected.")

        self._socket = sock
        self._reader = self._socket.makefile('rb')
        self._writer = self._socket.makefile('wb')
        self._connection_event.set()

        self._local_address = "%s:%d" % self._socket.getsockname()[:2]

        logger.debug("Established connection with %s (local address: %s).",
                     self._repr_remote(), self._local_address)

        for handler in self._on_connect_handlers:
            gevent.spawn(handler, plus)

    def finalize(self, reason=""):
        if not self.connected:
            return

        local_address = self._local_address

        self._socket = None
        self._reader = None
        self._writer = None
        self._local_address = None
        self._connection_event.clear()

        logger.debug("Terminated connection with %s (local address: %s): %s",
                     self._repr_remote(), local_address, reason)

        for handler in self._on_disconnect_handlers:
            gevent.spawn(handler)

    def disconnect(self, reason="Disconnection requested."):
        if not self.connected:
            return False

        try:
            self._socket.shutdown(socket.SHUT_RDWR)
            self._socket.close()
        except OSError as error:
            logger.warning("Couldn't disconnect from %s: %s.",
                           self._repr_remote(), error)
        finally:
            self.finalize(reason=reason)
        return True

    def _read(self):
        if not self.connected:
            raise OSError("Not connected.")

        try:
            with self._read_lock:
                if not self.connected:
                    raise OSError("Not connected.")
                data = self._reader.readline(self.MAX_MESSAGE_SIZE)
                # If there weren't a "\r\n" between the last message
                # and the EOF we would have a false positive here.
                # Luckily there is one.
                if len(data) > 0 and not data.endswith(b"\r\n"):
                    logger.error(
                        "The client sent a message larger than %d bytes (that "
                        "is MAX_MESSAGE_SIZE). Consider raising that value if "
                        "the message seemed legit.", self.MAX_MESSAGE_SIZE)
                    self.finalize("Client misbehaving.")
                    raise OSError("Message too long.")
        except OSError as error:
            if self.connected:
                logger.warning("Failed reading from socket: %s.", error)
                self.finalize("Read failed.")
                raise error
            else:
                return b""

        return data

    def _write(self, data):
        if not self.connected:
            raise OSError("Not connected.")

        if len(data + b'\r\n') > self.MAX_MESSAGE_SIZE:
            logger.error(
                "A message wasn't sent to %r because it was larger than %d "
                "bytes (that is MAX_MESSAGE_SIZE). Consider raising that "
                "value if the message seemed legit.", self._repr_remote(),
                self.MAX_MESSAGE_SIZE)
            # No need to call finalize.
            raise OSError("Message too long.")

        try:
            with self._write_lock:
                if not self.connected:
                    raise OSError("Not connected.")
                self._writer.write(data + b'\r\n')
                self._writer.flush()
        except OSError as error:
            self.finalize("Write failed.")
            logger.warning("Failed writing to socket: %s.", error)
            raise error


class PublicRemoteServiceServer(PublicRemoteServiceBase):
    def __init__(self, local_service, remote_address):
        super().__init__(remote_address)
        self.local_service = local_service

        self.pending_incoming_requests_threads = WeakSet()

        self.pending_outgoing_requests = dict()
        self.pending_outgoing_requests_results = dict()

    def finalize(self, reason=""):
        super().finalize(reason)

        for thread in self.pending_incoming_requests_threads:
            thread.kill(RPCError(reason), block=False)

        self.pending_incoming_requests_threads.clear()

    def handle(self, socket_):
        self.initialize(socket_, self.remote_address)
        self.run()

    def run(self):
        while True:
            try:
                data = self._read()
            except OSError:
                break

            if len(data) == 0:
                self.finalize("Connection closed.")
                break

            gevent.spawn(self.process_data, data)

    def process_data(self, data):
        try:
            message = json.loads(data.decode('utf-8'))
        except ValueError:
            self.disconnect("Bad request received")
            logger.warning("Cannot parse incoming message, discarding.")
            return

        # Using the keys in the data to check if it is request or response
        if {"__id", "__method", "__data"}.issubset(message.keys()):
            self.process_incoming_request(message)
        elif {"__id", "__data", "__error"}.issubset(message.keys()):
            self.process_incoming_response(message)
        else:
            self.disconnect("Bad request/response received")
            logger.warning(
                "Request/Response is missing some fields, ignoring.")

    def process_incoming_request(self, request):
        id_ = request["__id"]

        self.pending_incoming_requests_threads.add(gevent.getcurrent())

        response = {"__id": id_,
                    "__data": None,
                    "__error": None}

        method_name = request["__method"]

        if not hasattr(self.local_service, method_name):
            response["__error"] = "Method %s doesn't exist." % method_name
        else:
            method = getattr(self.local_service, method_name)

            if not getattr(method, "public_rpc_callable", False):
                response["__error"] = "Method %s isn't callable." % method_name
            else:
                try:
                    response["__data"] = method(**request["__data"])
                except Exception as error:
                    response["__error"] = "%s: %s\n%s" % \
                        (error.__class__.__name__, error,
                         traceback.format_exc())

        try:
            data = json.dumps(response).encode('utf-8')
        except (TypeError, ValueError):
            logger.warning("JSON encoding failed.", exc_info=True)
            return

        try:
            self._write(data)
        except OSError:
            return

    def process_incoming_response(self, response):
        id_ = response["__id"]

        if id_ not in self.pending_outgoing_requests:
            logger.warning("No pending request with id %s found.", id_)
            return

        request = self.pending_outgoing_requests.pop(id_)
        result = self.pending_outgoing_requests_results.pop(id_)
        error = response["__error"]

        if error is not None:
            err_msg = "%s signaled RPC for method %s was unsuccessful: %s." % (
                self.remote_address, request["__method"], error)
            logger.error(err_msg)
            result.set_exception(RPCError(error))
        else:
            result.set(response["__data"])

    def communicate(self, method, data):
        id_ = uuid.uuid4().hex

        request = {"__id": id_,
                   "__method": method,
                   "__data": data}

        result = gevent.event.AsyncResult()

        try:
            data = json.dumps(request).encode("utf-8")
        except (TypeError, ValueError):
            logger.error("JSON encoding failed.", exc_info=True)
            result.set_exception(RPCError("JSON encoding failed."))
            return result

        try:
            self._write(data)
        except OSError:
            result.set_exception(RPCError("Write failed."))
            return result

        self.pending_outgoing_requests[id_] = request
        self.pending_outgoing_requests_results[id_] = result

        return result

    def __getattr__(self, method):
        def run_callback(func, plus, result):
            data = result.value
            error = None if result.successful() else "%s" % result.exception
            try:
                if plus is None:
                    func(data, error=error)
                else:
                    func(data, plus, error=error)
            except Exception as error:
                logger.error("RPC callback for %s.%s raised exception.",
                             self.remote_service_coord.name, method,
                             exc_info=True)

        def remote_method(**data):
            callback = data.pop("callback", None)
            plus = data.pop("plus", None)
            result = self.communicate(method=method, data=data)
            if callback is not None:
                callback = functools.partial(run_callback, callback, plus)
                result.rawlink(functools.partial(gevent.spawn, callback))
            return result

        return remote_method


class PublicRemoteServiceClient(PublicRemoteServiceBase):
    def __init__(self, local_service, remote_address, remote_server,
                 auto_retry=None):
        super().__init__(remote_address)
        self.remote_server = remote_server
        # self.local_service = local_service

        self.pending_incoming_requests_threads = WeakSet()

        self.pending_outgoing_requests = dict()
        self.pending_outgoing_requests_results = dict()

        self.auto_retry = auto_retry

        self._loop = None

    def _repr_remote(self):
        return "%s:%d (%s)" % (self.remote_address + (self.remote_server,))

    def process_data(self, data):
        try:
            message = json.loads(data.decode('utf-8'))
        except ValueError:
            self.disconnect("Bad request received")
            logger.warning("Cannot parse incoming message, discarding.")
            return

        # Using the keys in the data to check if it is request or response
        if {"__id", "__method", "__data"}.issubset(message.keys()):
            self.process_incoming_request(message)
        elif {"__id", "__data", "__error"}.issubset(message.keys()):
            self.process_incoming_response(message)
        else:
            self.disconnect("Bad request/response received")
            logger.warning(
                "Request/Response is missing some fields, ignoring.")

    def process_incoming_request(self, request):
        id_ = request["__id"]

        self.pending_incoming_requests_threads.add(gevent.getcurrent())

        response = {"__id": id_,
                    "__data": None,
                    "__error": None}

        method_name = request["__method"]

        if not hasattr(self.local_service, method_name):
            response["__error"] = "Method %s doesn't exist." % method_name
        else:
            method = getattr(self.local_service, method_name)

            if not getattr(method, "public_rpc_callable", False):
                response["__error"] = "Method %s isn't callable." % method_name
            else:
                try:
                    response["__data"] = method(**request["__data"])
                except Exception as error:
                    response["__error"] = "%s: %s\n%s" % \
                        (error.__class__.__name__, error,
                         traceback.format_exc())

        try:
            data = json.dumps(response).encode('utf-8')
        except (TypeError, ValueError):
            logger.warning("JSON encoding failed.", exc_info=True)
            return

        try:
            self._write(data)
        except OSError:
            return

    def process_incoming_response(self, response):
        id_ = response["__id"]

        if id_ not in self.pending_outgoing_requests:
            logger.warning("No pending request with id %s found.", id_)
            return

        request = self.pending_outgoing_requests.pop(id_)
        result = self.pending_outgoing_requests_results.pop(id_)
        error = response["__error"]

        if error is not None:
            err_msg = "%s signaled RPC for method %s was unsuccessful: %s." % (
                self.remote_address, request["__method"], error)
            logger.error(err_msg)
            result.set_exception(RPCError(error))
        else:
            result.set(response["__data"])

    def communicate(self, method, data):
        id_ = uuid.uuid4().hex

        request = {"__id": id_,
                   "__method": method,
                   "__data": data}

        result = gevent.event.AsyncResult()

        try:
            data = json.dumps(request).encode("utf-8")
        except (TypeError, ValueError):
            logger.error("JSON encoding failed.", exc_info=True)
            result.set_exception(RPCError("JSON encoding failed."))
            return result

        try:
            self._write(data)
        except OSError:
            result.set_exception(RPCError("Write failed."))
            return result

        self.pending_outgoing_requests[id_] = request
        self.pending_outgoing_requests_results[id_] = result

        return result

    def __getattr__(self, method):
        def run_callback(func, plus, result):
            data = result.value
            error = None if result.successful() else "%s" % result.exception
            try:
                if plus is None:
                    func(data, error=error)
                else:
                    func(data, plus, error=error)
            except Exception as error:
                logger.error("RPC callback for %s.%s raised exception.",
                             self.remote_service_coord.name, method,
                             exc_info=True)

        def remote_method(**data):
            callback = data.pop("callback", None)
            plus = data.pop("plus", None)
            result = self.communicate(method=method, data=data)
            if callback is not None:
                callback = functools.partial(run_callback, callback, plus)
                result.rawlink(functools.partial(gevent.spawn, callback))
            return result

        return remote_method
