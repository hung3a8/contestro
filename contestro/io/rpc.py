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

from contestro import Address, get_service_address


logger = logging.getLogger(__name__)


class RPCError(Exception):
    pass


def rpc_method(func):
    func.rpc_callable = True
    return func


class RemoteServiceBase:
    MAX_MESSAGE_SIZE = 1024 * 1024

    def __init__(self, remote_address):
        self._local_address = None
        self.remote_address = remote_address
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

        logger.info("Established connection with %s (local address: %s).",
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

        logger.info("Terminated connection with %s (local address: %s): %s",
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
                # The client was terminated willingly; its correct termination
                # is handled in disconnect(), so here we can just return.
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
                # Does the same as self._socket.sendall.
                self._writer.write(data + b'\r\n')
                self._writer.flush()
        except OSError as error:
            self.finalize("Write failed.")
            logger.warning("Failed writing to socket: %s.", error)
            raise error


class RemoteServiceServer(RemoteServiceBase):
    def __init__(self, local_service, remote_address):
        super().__init__(remote_address)
        self.local_service = local_service

        self.pending_incoming_requests_threads = WeakSet()

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
        # Decode the incoming data.
        try:
            message = json.loads(data.decode('utf-8'))
        except ValueError:
            self.disconnect("Bad request received")
            logger.warning("Cannot parse incoming message, discarding.")
            return

        self.process_incoming_request(message)

    def process_incoming_request(self, request):
        # Validate the request.
        if not {"__id", "__method", "__data"}.issubset(request.keys()):
            self.disconnect("Bad request received")
            logger.warning("Request is missing some fields, ignoring.")
            return

        # Determine the ID.
        id_ = request["__id"]

        # Store the request.
        self.pending_incoming_requests_threads.add(gevent.getcurrent())

        # Build the response.
        response = {"__id": id_,
                    "__data": None,
                    "__error": None}

        method_name = request["__method"]

        if not hasattr(self.local_service, method_name):
            response["__error"] = "Method %s doesn't exist." % method_name
        else:
            method = getattr(self.local_service, method_name)

            if not getattr(method, "rpc_callable", False):
                response["__error"] = "Method %s isn't callable." % method_name
            else:
                try:
                    response["__data"] = method(**request["__data"])
                except Exception as error:
                    response["__error"] = "%s: %s\n%s" % \
                        (error.__class__.__name__, error,
                         traceback.format_exc())

        # Encode it.
        try:
            data = json.dumps(response).encode('utf-8')
        except (TypeError, ValueError):
            logger.warning("JSON encoding failed.", exc_info=True)
            return

        # Send it.
        try:
            self._write(data)
        except OSError:
            # Log messages have already been produced.
            return


class RemoteServiceClient(RemoteServiceBase):
    def __init__(self, remote_service_coord, auto_retry=None):
        super().__init__(get_service_address(remote_service_coord))
        self.remote_service_coord = remote_service_coord

        self.pending_outgoing_requests = dict()
        self.pending_outgoing_requests_results = dict()

        self.auto_retry = auto_retry

        self._loop = None

    def _repr_remote(self):
        return "%s:%d (%r)" % (self.remote_address +
                               (self.remote_service_coord,))

    def finalize(self, reason=""):
        super().finalize(reason)

        for result in self.pending_outgoing_requests_results.values():
            result.set_exception(RPCError(reason))

        self.pending_outgoing_requests.clear()
        self.pending_outgoing_requests_results.clear()

    def _connect(self):
        try:
            sock = gevent.socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(self.remote_address)
        except OSError as error:
            logger.debug("Couldn't connect to %s: %s.",
                         self._repr_remote(), error)
        else:
            self.initialize(sock, self.remote_service_coord)

    def _run(self):
        while True:
            self._connect()
            while not self.connected and self.auto_retry is not None:
                gevent.sleep(self.auto_retry)
                self._connect()
            if self.connected:
                self.run()
            if self.auto_retry is None:
                break

    def connect(self):
        """Connect and start the main loop.
        """
        if self._loop is not None and not self._loop.ready():
            raise RuntimeError("Already (auto-re)connecting")
        self._loop = gevent.spawn(self._run)

    def disconnect(self, reason="Disconnection requested."):
        """See RemoteServiceBase.disconnect."""
        if super().disconnect(reason=reason):
            self._loop.kill()
            self._loop = None

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
        # Decode the incoming data.
        try:
            message = json.loads(data.decode('utf-8'))
        except ValueError:
            self.disconnect("Bad response received")
            logger.warning("Cannot parse incoming message, discarding.")
            return

        self.process_incoming_response(message)

    def process_incoming_response(self, response):
        # Validate the response.
        if not {"__id", "__data", "__error"}.issubset(response.keys()):
            self.disconnect("Bad response received")
            logger.warning("Response is missing some fields, ignoring.")
            return

        # Determine the ID.
        id_ = response["__id"]

        if id_ not in self.pending_outgoing_requests:
            logger.warning("No pending request with id %s found.", id_)
            return

        request = self.pending_outgoing_requests.pop(id_)
        result = self.pending_outgoing_requests_results.pop(id_)
        error = response["__error"]

        if error is not None:
            err_msg = "%s signaled RPC for method %s was unsuccessful: %s." % (
                self.remote_service_coord, request["__method"], error)
            logger.error(err_msg)
            result.set_exception(RPCError(error))
        else:
            result.set(response["__data"])

    def execute_rpc(self, method, data):
        # Determine the ID.
        id_ = uuid.uuid4().hex

        # Build the request.
        request = {"__id": id_,
                   "__method": method,
                   "__data": data}

        result = gevent.event.AsyncResult()

        # Encode it.
        try:
            data = json.dumps(request).encode('utf-8')
        except (TypeError, ValueError):
            logger.error("JSON encoding failed.", exc_info=True)
            result.set_exception(RPCError("JSON encoding failed."))
            return result

        # Send it.
        try:
            self._write(data)
        except OSError:
            result.set_exception(RPCError("Write failed."))
            return result

        # Store it.
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
            result = self.execute_rpc(method=method, data=data)
            if callback is not None:
                callback = functools.partial(run_callback, callback, plus)
                result.rawlink(functools.partial(gevent.spawn, callback))
            return result

        return remote_method
