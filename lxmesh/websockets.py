__all__ = ['NonblockingWSClient']

import contextlib
import logging
import os
import socket
import ssl
import time
import typing
import urllib.parse
from collections import deque

import websockets.connection
import websockets.exceptions
import websockets.frames
import websockets.uri
try:
    from websockets.client import ClientProtocol as WSClientProtocol  # type: ignore[attr-defined]  # Will exist in a future version.
except ImportError:
    from websockets.client import ClientConnection as WSClientProtocol


class NonblockingWSClient:
    # Please note that if a SSL socket is used, instances of this class can
    # only be used is edge-triggered I/O anyway; see
    # https://docs.python.org/dev/library/ssl.html#notes-on-non-blocking-sockets.
    # Also, this class transforms SSLWantReadError and SSLWantWriteError to
    # BlockingIOError.
    def __init__(self,
                 uri: str,
                 *args: typing.Any,
                 text_encoding: str = 'utf-8',
                 bytes_encoding: str | None = None,
                 raise_write_blocking: bool = False,
                 close_timeout: float = 10,
                 ssl_options: typing.Any = None,
                 **kw: typing.Any) -> None:
        if args:
            logging.warning("Unexpected positional arguments to {}: {}.".format(type(self).__name__, ", ".join("{!r}".format(arg) for arg in args)))
        if kw:
            logging.warning("Unexpected keyword arguments to {}: {}.".format(type(self).__name__, ", ".join("{}={!r}".format(name, value) for name, value in kw.items())))
        self.uri = uri
        self.text_encoding = text_encoding
        self.bytes_encoding = bytes_encoding
        self.raise_write_blocking = raise_write_blocking
        self.close_timeout = close_timeout

        self.resource:  str | None              = None
        self.sock:      socket.socket | None    = None
        self.protocol:  WSClientProtocol | None = None

    def connect(self) -> None:
        if self.sock is not None:
            raise ValueError("socket is already connected")

        parsed_uri = urllib.parse.urlparse(self.uri)
        if parsed_uri.scheme not in ('ws+unix',):
            raise ValueError("unsupported scheme for URI '{}'".format(self.uri))
        if self.resource is not None:
            try:
                path, query = self.resource.split('?', 1)
            except ValueError:
                path, query = self.resource, ''
        else:
            path = '/'
            if parsed_uri.params:
                path += ';' + parsed_uri.params
            if parsed_uri.fragment:
                path += '#' + parsed_uri.fragment
            query = parsed_uri.query
        wsuri = websockets.uri.WebSocketURI(secure=False, host='localhost', port=80,
                                            path=path, query=query, username=None, password=None)

        self.protocol = WSClientProtocol(wsuri)
        request = self.protocol.connect()
        self.protocol.send_request(request)

        self.close_time:            float | None                                = None
        self.pending_frame_opcode:  websockets.frames.Opcode | None             = None
        self.pending_read:          bytearray | None                            = None
        self.pending_write:         bytearray                                   = bytearray()
        self.pending_events:        deque[websockets.connection.Event]          = deque()
        self.protocol_error:        websockets.exceptions.ProtocolError | None  = None

        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.setblocking(False)
        try:
            self.sock.connect(os.fsencode(parsed_uri.path))
        except BlockingIOError:
            if self.raise_write_blocking:
                raise
        except BaseException:
            self.sock = None
            self.protocol = None
            raise
        else:
            self.send()

    def fileno(self) -> int:
        if self.sock is None:
            raise ValueError("socket is closed")
        return self.sock.fileno()

    @property
    def closed(self) -> bool:
        return self.sock is None

    def close(self) -> None:
        if self.sock is None or self.protocol is None:
            return
        try:
            self.protocol.send_close()
        except websockets.exceptions.InvalidState:
            pass  # already closing
        else:
            self.send()

    def force_close(self) -> None:
        if self.sock is not None:
            self.sock.close()
            self.sock = None
            self.protocol = None

    def close_expected(self) -> float:
        if self.sock is None or self.protocol is None:
            raise ValueError("socket is already closed or not connected")
        now = time.monotonic()
        if self.close_time is not None:
            if now >= self.close_time:
                self.force_close()
            return max(0, self.close_time - now)
        elif self.protocol.close_expected():
            self.close_time = now + self.close_timeout
            return self.close_timeout
        else:
            return float('inf')

    def recv(self) -> bytes | str:
        try:
            while self.sock is not None and self.protocol is not None and not self.pending_events:
                try:
                    data = self.sock.recv(4096)
                except ssl.SSLWantWriteError:
                    # Any exceptions in the send() call means that we can't do
                    # any reads from the socket anyway.
                    self.send()
                    continue
                if not data:
                    self.protocol.receive_eof()
                    self.force_close()
                    break
                try:
                    self.protocol.receive_data(data)
                except websockets.exceptions.ProtocolError as e:
                    self.protocol_error = e
                    self.force_close()
                finally:
                    self.pending_events = deque(self.protocol.events_received())
        except (BlockingIOError, ssl.SSLWantReadError, ssl.SSLWantWriteError):
            pass

        try:
            while True:
                try:
                    event = self.pending_events.popleft()
                except IndexError:
                    if self.protocol_error is not None:
                        raise self.protocol_error from None
                    else:
                        raise BlockingIOError() from None
                if not isinstance(event, websockets.frames.Frame):
                    continue
                match event.opcode:
                    case websockets.frames.Opcode.CONT:
                        if self.pending_read is None:
                            # This should never happen, as guaranteed by python-websockets.
                            continue
                        self.pending_read.extend(event.data)
                        if event.fin:
                            try:
                                if self.pending_frame_opcode == websockets.frames.Opcode.TEXT:
                                    return self.pending_read.decode(self.text_encoding)
                                elif self.bytes_encoding is not None:
                                    return self.pending_read.decode(self.bytes_encoding)
                                else:
                                    return self.pending_read
                            finally:
                                self.pending_read = None
                                self.pending_frame_opcode = None
                    case websockets.frames.Opcode.TEXT:
                        if not event.fin:
                            self.pending_read = bytearray(event.data)
                            self.pending_frame_opcode = event.opcode
                            continue
                        return event.data.decode(self.text_encoding)
                    case websockets.frames.Opcode.BINARY:
                        if not event.fin:
                            self.pending_read = bytearray(event.data)
                            self.pending_frame_opcode = event.opcode
                            continue
                        if self.bytes_encoding is not None:
                            return event.data.decode(self.bytes_encoding)
                        else:
                            return event.data
        finally:
            # If send() is expected to raise BlockingIOError so that the
            # WebSocket can be used is level-triggered polling, the user is
            # expected to call send() after recv() anyway. The test is not
            # technically necessary, but is included in order to discourage
            # reliancy on the send() call.
            #
            # Any other exceptions must be supressed, as data would be lost
            # otherwise.
            if not self.raise_write_blocking:
                with contextlib.suppress(Exception):
                    self.send()

    def send(self) -> None:
        if self.sock is None or self.protocol is None:
            return
        try:
            while self.pending_write:
                sent = self.sock.send(self.pending_write)
                del self.pending_write[:sent]
            for data in self.protocol.data_to_send():
                if not data:
                    self.sock.shutdown(socket.SHUT_WR)
                    return
                self.pending_write = bytearray(data)
                while self.pending_write:
                    sent = self.sock.send(self.pending_write)
                    del self.pending_write[:sent]
        except (BlockingIOError, ssl.SSLWantReadError, ssl.SSLWantWriteError):
            if self.raise_write_blocking:
                raise BlockingIOError() from None

    def heartbeat(self) -> None:
        if self.sock is None or self.protocol is None:
            return
        try:
            self.protocol.send_pong(b'beep')
        except websockets.exceptions.InvalidState:
            pass  # already closing
        else:
            self.send()
