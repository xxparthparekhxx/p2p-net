"""NAT fallback relay: the protocol constants shared by the introduction
server and the peers, and the peer side of the protocol (RelayClient).

A peer the introduction server cannot dial back keeps one persistent
"channel" connection to the server. Another peer that cannot reach it
directly opens a one-shot "request" connection and asks the server to
forward one framed DHT message over that channel; the server hands the
reply back. The relay never looks inside the messages, and a peer
verifies every record by its Ed25519 signature as usual, so the relay is
not trusted for content. Both connections are made to the introduction
server's own port and open with one unframed JSON object (like a join);
everything after that is length-prefixed frames (see kademlia_dht.py).

Channel:
  peer -> server   {"type": "relay_register", "virtual_ip", "token"}
  server -> peer   frame {"type": "relay_registered"}, or {"type": "error"}
  then JSON frames both ways:
  server -> peer   {"type": "relayed", "id", "from", "payload": base64}
  peer -> server   {"type": "relay_reply", "id", "payload": base64}, or
                   {"type": "relay_reply", "id", "error"}
  peer -> server   {"type": "ping"}      server -> peer  {"type": "pong"}

Request:
  peer -> server   {"type": "relay", "from", "token", "to"}
  server -> peer   frame {"type": "relay_ready"}, or {"type": "relay_failed"}
  peer -> server   frame: the DHT request itself (at most 1 MB)
  server -> peer   frame {"type": "relay_reply", "payload": base64}, or
                   {"type": "relay_failed", "error"}

`virtual_ip` and `token` are the values from the join reply: the token is
what stops another peer from registering a channel as, or relaying as, a
peer it is not.
"""

import asyncio
import base64
import json
from typing import Awaitable, Callable, Optional

from kademlia_dht import (
    MAX_MESSAGE_SIZE,
    READ_TIMEOUT,
    connect,
    read_frame,
    safe_text,
    write_frame,
)

# A relayed message is an ordinary framed DHT message and obeys its 1 MB cap,
# in both directions. The JSON frames that carry it base64-encode it (4/3 the
# size), so they get a bigger frame cap.
MAX_RELAYED_MESSAGE_SIZE = MAX_MESSAGE_SIZE
MAX_RELAY_FRAME_SIZE = 2 * MAX_MESSAGE_SIZE

# The channel is quiet between requests, so the peer pings on it to keep a
# NAT's idle-connection mapping alive and to notice a dead server; either
# side gives up on a channel that has been silent for RELAY_IDLE_TIMEOUT
# (a few missed pings).
RELAY_PING_INTERVAL = 25
RELAY_IDLE_TIMEOUT = 90

# How long the server waits for the relayed peer's reply. The sender waits
# that, plus a READ_TIMEOUT of slack, for the server's answer.
RELAY_TIMEOUT = 15

# A dropped channel is reopened after RELAY_RECONNECT_MIN seconds, doubling
# up to RELAY_RECONNECT_MAX while the server stays away.
RELAY_RECONNECT_MIN = 1
RELAY_RECONNECT_MAX = 30
# How long RelayClient.start() waits for the first registration to succeed.
RELAY_REGISTER_WAIT = 15
# A write on the channel that hasn't drained in this long means the server
# stopped reading; the channel is dropped and reopened rather than left
# blocking the read loop.
RELAY_WRITE_TIMEOUT = READ_TIMEOUT


class RelayClient:
    """The peer side of the relay.

    start() keeps a channel open to the introduction server, so peers that
    cannot reach us directly can send us requests through it; `handler`
    answers each one (an async bytes -> reply bytes, or None; for a DHT node
    that is KademliaNode.dispatch). request() sends a request to another
    peer through the server. `virtual_ip` and `token` come from the join
    reply.
    """

    def __init__(self, server_address, virtual_ip: str, token: str,
                 handler: Callable[[bytes], Awaitable[Optional[bytes]]]):
        self.server_address = server_address
        self.virtual_ip = virtual_ip
        self.token = token
        self.handler = handler
        self._task = None
        self._registered = asyncio.Event()

    async def start(self):
        """Open the channel and keep it open, reconnecting, until stop().
        Returns once the server accepted the registration, or after
        RELAY_REGISTER_WAIT seconds without one (it keeps trying)."""
        self._task = asyncio.create_task(self._run())
        try:
            await asyncio.wait_for(self._registered.wait(),
                                   RELAY_REGISTER_WAIT)
        except asyncio.TimeoutError:
            print(f"Relay channel for {self.virtual_ip} is not registered "
                  f"yet; still trying")

    async def stop(self):
        if self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None

    async def request(self, to_vip: str, payload: bytes) -> Optional[bytes]:
        """Send one framed DHT request to the peer at `to_vip` through the
        server and return its framed reply, or None if there is none."""
        if len(payload) > MAX_RELAYED_MESSAGE_SIZE:
            print(f"Not relaying a {len(payload)}-byte message: over the "
                  f"{MAX_RELAYED_MESSAGE_SIZE}-byte cap")
            return None
        try:
            reader, writer = await connect(*self.server_address)
        except Exception as e:
            print(f"Relay request to {safe_text(to_vip)} failed: can't reach "
                  f"the introduction server ({e})")
            return None
        try:
            writer.write(json.dumps({
                'type': 'relay', 'from': self.virtual_ip,
                'token': self.token, 'to': to_vip}).encode())
            await writer.drain()
            answer = await self._read_json(reader)
            if answer.get('type') == 'relay_ready':
                await write_frame(writer, payload)
                answer = await self._read_json(
                    reader, header_timeout=RELAY_TIMEOUT + READ_TIMEOUT)
            if answer.get('type') != 'relay_reply':
                raise ConnectionError(safe_text(answer.get('error')))
            reply = base64.b64decode(answer['payload'], validate=True)
            if len(reply) > MAX_RELAYED_MESSAGE_SIZE:
                raise ValueError("reply is over the size cap")
            return reply
        except Exception as e:
            print(f"Relay request to {safe_text(to_vip)} failed: {e}")
            return None
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    @staticmethod
    async def _read_json(reader, header_timeout=None) -> dict:
        frame = await read_frame(reader, MAX_RELAY_FRAME_SIZE,
                                 header_timeout=header_timeout)
        message = json.loads(frame.decode())
        if not isinstance(message, dict):
            raise ValueError("relay frame is not a JSON object")
        return message

    async def _run(self):
        delay = RELAY_RECONNECT_MIN
        while True:
            writer = None
            try:
                reader, writer = await connect(*self.server_address)
                writer.write(json.dumps({
                    'type': 'relay_register', 'virtual_ip': self.virtual_ip,
                    'token': self.token}).encode())
                await writer.drain()
                ack = await self._read_json(reader)
                if ack.get('type') != 'relay_registered':
                    raise ConnectionError(
                        f"registration refused: {safe_text(ack.get('error'))}")
                print(f"Relay channel open for virtual IP {self.virtual_ip}")
                self._registered.set()
                delay = RELAY_RECONNECT_MIN
                pinger = asyncio.create_task(self._ping_loop(writer))
                try:
                    while True:
                        message = await self._read_json(
                            reader, header_timeout=RELAY_IDLE_TIMEOUT)
                        await self._handle_message(writer, message)
                finally:
                    pinger.cancel()
            except Exception as e:
                print(f"Relay channel for {self.virtual_ip} dropped ({e}); "
                      f"reconnecting in {delay}s")
            finally:
                if writer is not None:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
            await asyncio.sleep(delay)
            delay = min(delay * 2, RELAY_RECONNECT_MAX)

    @staticmethod
    async def _send(writer, message: dict):
        """Write one JSON frame on the channel, bounded by RELAY_WRITE_TIMEOUT."""
        try:
            await asyncio.wait_for(
                write_frame(writer, json.dumps(message).encode()),
                RELAY_WRITE_TIMEOUT)
        except asyncio.TimeoutError:
            writer.transport.abort()
            raise ConnectionError("the server is not reading the channel")

    async def _ping_loop(self, writer):
        try:
            while True:
                await asyncio.sleep(RELAY_PING_INTERVAL)
                await self._send(writer, {'type': 'ping'})
        except Exception:
            pass  # the read loop notices a broken connection

    async def _handle_message(self, writer, message: dict):
        kind = message.get('type')
        if kind == 'pong':
            return
        if kind != 'relayed':
            print(f"Ignoring a {safe_text(kind)} frame on the relay channel")
            return
        reply = await self._answer(message)
        out = {'type': 'relay_reply', 'id': message.get('id')}
        if reply is None:
            out['error'] = 'could not handle the relayed message'
        else:
            out['payload'] = base64.b64encode(reply).decode()
        await self._send(writer, out)

    async def _answer(self, message: dict) -> Optional[bytes]:
        """The handler's reply to one relayed request, or None."""
        try:
            payload = base64.b64decode(message.get('payload'), validate=True)
            if len(payload) > MAX_RELAYED_MESSAGE_SIZE:
                return None
            reply = await self.handler(payload)
        except Exception as e:
            print(f"Error handling a relayed message: {e}")
            return None
        if reply is not None and len(reply) > MAX_RELAYED_MESSAGE_SIZE:
            return None
        return reply
