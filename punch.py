"""TCP hole punching: the protocol constants shared by the introduction server
and the peers, and the peer side of the protocol (PunchClient).

Two peers that cannot dial each other (each behind a NAT that drops
unsolicited inbound connections) can still get a direct TCP connection if
both call connect() at the other's public endpoint at about the same time,
from the port the NAT already maps for them: each NAT sees an outbound SYN,
has (or creates) a mapping, and lets the other side's SYN through (a TCP
"simultaneous open"). The introduction server coordinates it and tells each
peer the endpoint it *observed* for the other. The peers never tell the
server where they are, and the server dials no one.

Which endpoint the server observed: a peer that can punch opens its relay
channel (relay.py) from its listening port, bound with SO_REUSEADDR and
SO_REUSEPORT so it shares the port with the listener. The address that
channel's connection comes from is then the NAT's mapping of the listening
port, which is the one a punch uses; the channel is kept alive by the relay's
pings. (A peer the server could dial back needs no mapping: its endpoint is
the address the dial-back reached.) The punch itself needs no further
connection from that port, which would be a second connection from one local
port to the same server address, and TCP does not allow that.

  A -> server   {"type": "punch", "from", "token", "to"}   (any port)
  server -> B   on B's relay channel: {"type": "punch_go", "id", "from",
                "peer": {"ip", "port"}}      (the endpoint observed for A)
  server -> A   frame {"type": "punch_go", "id", "peer": {"ip", "port"}}
                (the endpoint observed for B), or {"type": "punch_failed",
                "error"}; A keeps the connection open until its punch is
                over, which is when the server frees the punch's slot

`id` is a random secret the server hands to those two peers only. Both then
connect() to `peer` for up to PUNCH_WINDOW seconds, retrying, while also
accepting on the listening port (one side's SYN can reach the other's
listener instead of crossing). Whichever connection comes up, both ends send
the frame `PUNCH <id>` and check the other's: a stranger that reaches the
port does not know the id. A connection that reached the listener must also
come from the IP the server named.

The connection then carries DHT traffic in both directions, many requests at
once. A frame is a one-byte kind, a 4-byte request id and the payload:

  1 request   2 reply   3 no reply (the peer could not answer that request)

The channel is kept for later requests to that peer until it has been silent
for PUNCH_IDLE_TIMEOUT (NAT mappings are per flow, so a new connection to the
same peer would have to be punched again). Records are verified end to end
as on any other path; the channel is plain TCP like the rest. Every socket
that shares the listening port resets its connection when it closes instead
of leaving a TIME_WAIT entry that would block the next connect() from that
port to the same peer (stun.abort_on_close).
"""

import asyncio
import ipaddress
import json
from typing import Awaitable, Callable, Dict, Optional, Tuple

import kademlia_dht
from kademlia_dht import (
    MAX_MESSAGE_SIZE,
    PUNCH_HELLO,
    READ_TIMEOUT,
    Node,
    read_frame,
    safe_text,
    write_frame,
)
from relay import read_json_frame
from stun import abort_on_close, connect_from

# How long both peers keep trying to connect to each other after the server
# says go; one attempt is a connect() of at most PUNCH_ATTEMPT_TIMEOUT, with
# PUNCH_RETRY_INTERVAL between attempts. The hello exchange on a new
# connection gets PUNCH_HANDSHAKE_TIMEOUT.
PUNCH_WINDOW = 6
PUNCH_ATTEMPT_TIMEOUT = 2
PUNCH_RETRY_INTERVAL = 0.25
PUNCH_HANDSHAKE_TIMEOUT = 3
# How long the server keeps a punch's slot after the go if the initiator has
# not closed its connection: the window, a handshake and a second of slack.
PUNCH_SESSION_TIMEOUT = PUNCH_WINDOW + PUNCH_HANDSHAKE_TIMEOUT + 1

# A peer that a punch failed for is not tried again for this long: without
# it, every request to a peer behind a symmetric NAT would pay for a punch.
PUNCH_RETRY_DELAY = 60

# A punched channel is closed after this long without a frame from the peer.
PUNCH_IDLE_TIMEOUT = 60
# A request waits this long for its reply; a write that has not drained in
# PUNCH_WRITE_TIMEOUT means the peer stopped reading and drops the channel.
PUNCH_REQUEST_TIMEOUT = READ_TIMEOUT
PUNCH_WRITE_TIMEOUT = READ_TIMEOUT

# Per peer: punched channels, requests in flight on one channel (each
# direction), punches this peer starts at once, and punches the server asks
# it to join at once.
MAX_PUNCHED_CHANNELS = 32
PUNCH_MAX_INFLIGHT = 16
PUNCH_MAX_ATTEMPTS = 4
PUNCH_MAX_RESPONSES = 4

# The longest punch id the peer accepts from the server, and so the longest
# hello (PUNCH_HELLO and the id).
MAX_PUNCH_ID_SIZE = 64
MAX_HELLO_SIZE = len(PUNCH_HELLO) + MAX_PUNCH_ID_SIZE

# A channel frame is a 5-byte header and a DHT message of at most 1 MB.
MAX_PUNCH_FRAME_SIZE = 5 + MAX_MESSAGE_SIZE
REQUEST, REPLY, NO_REPLY = 1, 2, 3

Handler = Callable[[bytes], Awaitable[Optional[bytes]]]


class PunchedChannel:
    """A punched TCP connection to one peer, carrying framed DHT requests
    both ways, many at once, matched to their replies by request id.

    `handler` answers the peer's requests (for a DHT node that is
    KademliaNode.dispatch). Closing it, for any reason, fails the requests
    still waiting for a reply.
    """

    def __init__(self, virtual_ip: str, reader, writer, handler: Handler,
                 on_close: Callable[["PunchedChannel"], None]):
        self.virtual_ip = virtual_ip
        self.reader, self.writer = reader, writer
        self.handler = handler
        self.closed = False
        self._on_close = on_close
        self._pending: Dict[int, asyncio.Future] = {}
        self._handlers = set()
        self._next_id = 0
        self._write_lock = asyncio.Lock()
        self._task = asyncio.create_task(self._run())

    async def request(self, payload: bytes) -> Optional[bytes]:
        """The peer's reply to `payload`, or None if it has none. Raises
        ConnectionError if the channel is closed, busy or the peer is not
        answering."""
        if self.closed:
            raise ConnectionError("the channel is closed")
        if len(self._pending) >= PUNCH_MAX_INFLIGHT:
            raise ConnectionError("too many requests in flight")
        self._next_id = (self._next_id + 1) & 0xFFFFFFFF
        request_id = self._next_id
        future = asyncio.get_running_loop().create_future()
        self._pending[request_id] = future
        try:
            await self._send(REQUEST, request_id, payload)
            return await asyncio.wait_for(future, PUNCH_REQUEST_TIMEOUT)
        except asyncio.TimeoutError:
            raise ConnectionError(f"no reply within {PUNCH_REQUEST_TIMEOUT}s")
        finally:
            del self._pending[request_id]

    async def _send(self, kind: int, request_id: int, payload: bytes = b""):
        async with self._write_lock:
            try:
                await asyncio.wait_for(
                    write_frame(self.writer, bytes([kind])
                                + request_id.to_bytes(4, "big") + payload),
                    PUNCH_WRITE_TIMEOUT)
            except asyncio.TimeoutError:
                self.writer.transport.abort()
                raise ConnectionError("the peer is not reading the channel")

    async def _run(self):
        try:
            while True:
                frame = await read_frame(self.reader, MAX_PUNCH_FRAME_SIZE,
                                         header_timeout=PUNCH_IDLE_TIMEOUT)
                await self._handle_frame(frame)
        except Exception as e:
            reason = e or type(e).__name__
            print(f"Punched channel to {safe_text(self.virtual_ip)} closed: "
                  f"{reason}")
        finally:
            self.close()

    async def _handle_frame(self, frame: bytes):
        if len(frame) < 5:
            raise ValueError("frame is shorter than its header")
        kind, request_id = frame[0], int.from_bytes(frame[1:5], "big")
        payload = frame[5:]
        if kind == REQUEST:
            if len(self._handlers) >= PUNCH_MAX_INFLIGHT:
                await self._send(NO_REPLY, request_id)   # busy: don't queue it
                return
            task = asyncio.create_task(self._serve(request_id, payload))
            self._handlers.add(task)
            task.add_done_callback(self._handlers.discard)
        elif kind in (REPLY, NO_REPLY):
            future = self._pending.get(request_id)
            if future is not None and not future.done():
                future.set_result(payload if kind == REPLY else None)
        else:
            raise ValueError(f"unknown frame kind {kind}")

    async def _serve(self, request_id: int, payload: bytes):
        """Answer one request of the peer's."""
        try:
            reply = await self.handler(payload)
            if reply is not None and len(reply) > MAX_MESSAGE_SIZE:
                reply = None
        except Exception as e:
            print(f"Error handling a request on a punched channel: {e}")
            reply = None
        try:
            if reply is None:
                await self._send(NO_REPLY, request_id)
            else:
                await self._send(REPLY, request_id, reply)
        except Exception as e:
            print(f"Could not answer on the punched channel to "
                  f"{safe_text(self.virtual_ip)}: {e}")
            self.close()

    def close(self):
        """Close the channel and fail what is waiting on it. Safe to repeat."""
        if self.closed:
            return
        self.closed = True
        for future in self._pending.values():
            if not future.done():
                future.set_exception(ConnectionError("the channel closed"))
        for task in self._handlers:
            task.cancel()
        self.writer.close()
        if self._task is not asyncio.current_task():
            self._task.cancel()
        self._on_close(self)

    async def wait_closed(self):
        await asyncio.gather(self._task, *self._handlers,
                             return_exceptions=True)
        try:
            await self.writer.wait_closed()
        except Exception:
            pass


class PunchClient:
    """The peer side of hole punching.

    request() sends a DHT request to a contact over a punched connection,
    punching one first if there is none (at most one punch per contact at a
    time, and none for PUNCH_RETRY_DELAY after one failed). handle_go()
    joins a punch the server started for another peer, accept() takes the
    inbound connection of a punch that reached our listener first, and the
    channels that result are reused until they go idle. `local_addr` is our
    listening address: the connections to the peer are made from that port.
    `virtual_ip` and `token` come from the join reply; `handler` answers
    requests that arrive on a punched channel.
    """

    def __init__(self, server_address, virtual_ip: str, token: str,
                 local_addr: Tuple[str, int], handler: Handler):
        self.server_address = server_address
        self.virtual_ip = virtual_ip
        self.token = token
        self.local_addr = local_addr
        self.handler = handler
        self.channels: Dict[str, PunchedChannel] = {}
        self._attempts: Dict[str, asyncio.Task] = {}   # punches we started
        self._responders = set()                       # punches we joined
        self._retry_after: Dict[str, float] = {}       # virtual ip -> loop time
        # Punches in progress: id -> (IP the peer must come from, future that
        # takes the (reader, writer) of a connection that reached our listener).
        self._expected: Dict[str, Tuple[str, asyncio.Future]] = {}
        self._stopped = False

    # --- Using punched channels ---

    async def request(self, node: Node, payload: bytes) -> Optional[bytes]:
        """Send one framed DHT request to `node` over a punched connection and
        return its framed reply, or None if there is no punched path (not
        possible, not worth retrying yet, or it failed): the caller then
        falls back to the relay."""
        vip = node.virtual_ip
        if self._stopped or vip is None or len(payload) > MAX_MESSAGE_SIZE:
            return None
        channel = self.channels.get(vip)
        if channel is None:
            channel = await self._punch(vip)
            if channel is None:
                return None
        try:
            return await channel.request(payload)
        except Exception as e:
            print(f"Request over the punched connection to "
                  f"{safe_text(vip)} failed: {e}")
            channel.close()
            self._fail(vip)
            return None

    def _fail(self, vip: str):
        now = asyncio.get_running_loop().time()
        if len(self._retry_after) >= 4 * MAX_PUNCHED_CHANNELS:
            self._retry_after = {v: t for v, t in self._retry_after.items()
                                 if t > now}
        self._retry_after[vip] = now + PUNCH_RETRY_DELAY

    async def _punch(self, vip: str) -> Optional[PunchedChannel]:
        """The channel to `vip` from a new punch, joining one already under
        way; None if it failed, is in its retry delay, or this peer is
        already running PUNCH_MAX_ATTEMPTS punches."""
        if asyncio.get_running_loop().time() < self._retry_after.get(vip, 0):
            return None
        attempt = self._attempts.get(vip)
        if attempt is None:
            if len(self._attempts) >= PUNCH_MAX_ATTEMPTS:
                return None
            attempt = self._attempts[vip] = asyncio.create_task(
                self._initiate(vip))
            attempt.add_done_callback(
                lambda task: self._attempts.pop(vip, None)
                if self._attempts.get(vip) is task else None)
        # Shielded: the punch belongs to the client, not to the first caller.
        try:
            return await asyncio.shield(attempt)
        except asyncio.CancelledError:
            if attempt.cancelled():
                return None   # stop() cancelled the punch, not this caller
            raise

    async def _initiate(self, vip: str) -> Optional[PunchedChannel]:
        try:
            reader, writer = await kademlia_dht.connect(*self.server_address)
            try:
                writer.write(json.dumps({
                    'type': 'punch', 'from': self.virtual_ip,
                    'token': self.token, 'to': vip}).encode())
                await writer.drain()
                go = await read_json_frame(reader)
                if go.get('type') != 'punch_go':
                    raise ConnectionError(safe_text(go.get('error')))
                channel = await self._open(vip, go)
            finally:
                await self._close(writer)
        except Exception as e:
            print(f"Hole punch to {safe_text(vip)} failed: {e}")
            channel = None
        if channel is None:
            self._fail(vip)
        else:
            self._retry_after.pop(vip, None)
        return channel

    # --- Joining a punch another peer started ---

    def handle_go(self, message: dict):
        """A punch_go from the server on our relay channel: another peer wants
        to connect to us, and this is where it is. Starts connecting as a task.
        Dropped if we are stopping or already joining as many as we will."""
        from_vip = message.get('from')
        if not isinstance(from_vip, str):
            return
        if self._stopped or len(self._responders) >= PUNCH_MAX_RESPONSES:
            print(f"Ignoring a punch from {safe_text(from_vip)}")
            return
        task = asyncio.create_task(self._join(from_vip, message))
        self._responders.add(task)
        task.add_done_callback(self._responders.discard)

    async def _join(self, from_vip: str, go: dict):
        try:
            await self._open(from_vip, go)
        except Exception as e:
            print(f"Could not join the punch from {safe_text(from_vip)}: {e}")

    # --- Opening a channel: both peers run this after the server's go ---

    async def _open(self, vip: str, go: dict) -> Optional[PunchedChannel]:
        """Connect to the endpoint the server named, while accepting the
        peer's connection on the listening port, and return the channel that
        comes up first (None if neither does in PUNCH_WINDOW)."""
        punch_id, (ip, port) = self._parse_go(go)
        if punch_id in self._expected:
            raise ValueError("the server reused a punch id")
        inbound = asyncio.get_running_loop().create_future()
        self._expected[punch_id] = (ip, inbound)
        dial = asyncio.create_task(self._dial(ip, port, punch_id))
        connection = None
        try:
            await asyncio.wait({dial, inbound},
                               return_when=asyncio.FIRST_COMPLETED)
            if inbound.done():
                connection = inbound.result()
            elif dial.exception() is None:
                connection = dial.result()
            else:
                print(f"No punched connection to {safe_text(vip)}: "
                      f"{dial.exception()}")
        finally:
            del self._expected[punch_id]
            dial.cancel()
            await asyncio.gather(dial, return_exceptions=True)
            inbound.cancel()
            # The other path can come up in the same moment; one connection
            # is enough, so close the surplus one.
            for other in (inbound, dial):
                if (other.done() and not other.cancelled()
                        and other.exception() is None
                        and other.result() is not connection):
                    await self._close(other.result()[1])
        if connection is None:
            return None
        return self._add_channel(vip, *connection)

    @staticmethod
    def _parse_go(go: dict):
        """(punch id, (ip, port)) from the server's punch_go, or ValueError."""
        punch_id, peer = go.get('id'), go.get('peer')
        if not (isinstance(punch_id, str)
                and 0 < len(punch_id) <= MAX_PUNCH_ID_SIZE
                and isinstance(peer, dict)):
            raise ValueError("malformed punch_go")
        ip, port = peer.get('ip'), peer.get('port')
        try:
            if not isinstance(ip, str):
                raise ValueError
            address = ipaddress.ip_address(ip)
        except ValueError:
            raise ValueError("punch_go names an address that is not an IP")
        if address.is_unspecified or address.is_multicast:
            raise ValueError("punch_go names an address nobody has")
        ip = str(address)
        if not (isinstance(port, int) and not isinstance(port, bool)
                and 0 < port < 65536):
            raise ValueError("punch_go names an invalid port")
        return punch_id, (ip, port)

    async def _dial(self, ip: str, port: int, punch_id: str):
        """Connect to (ip, port) from the listening port, again and again for
        PUNCH_WINDOW seconds, until a connection exchanges hellos with the
        peer. A refused or dropped attempt just means the other side's NAT has
        not let us in yet (or the other peer is not connecting yet)."""
        loop = asyncio.get_running_loop()
        hello = PUNCH_HELLO + punch_id.encode()
        deadline = loop.time() + PUNCH_WINDOW
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise TimeoutError(f"no connection within {PUNCH_WINDOW}s")
            writer = None
            try:
                reader, writer = await connect_from(
                    self.local_addr, (ip, port),
                    min(PUNCH_ATTEMPT_TIMEOUT, remaining))
                await write_frame(writer, hello)
                answer = await asyncio.wait_for(
                    read_frame(reader, MAX_HELLO_SIZE), PUNCH_HANDSHAKE_TIMEOUT)
                if self._expects(answer, ip):
                    result, writer = (reader, writer), None   # keep it open
                    return result
            except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError,
                    ValueError):
                pass
            finally:
                if writer is not None:
                    await self._close(writer)
            await asyncio.sleep(PUNCH_RETRY_INTERVAL)

    def _expects(self, hello: bytes, ip: str) -> bool:
        """Is `hello` the hello of a punch in progress with the peer at `ip`?
        Usually the peer sends the hello of the punch we are running, but if
        both peers started a punch to each other at once the two connections
        are the same TCP connection, and each end then sees the other's
        punch id: that is the same peer, so it is accepted too."""
        if not hello.startswith(PUNCH_HELLO):
            return False
        expected = self._expected.get(
            hello[len(PUNCH_HELLO):].decode("utf-8", "replace"))
        return (expected is not None and not expected[1].done()
                and ipaddress.ip_address(expected[0]) == ipaddress.ip_address(ip))

    async def accept(self, reader, writer, hello: bytes):
        """An inbound connection whose first frame was a PUNCH hello (see
        KademliaNode.handle_connection). It is kept only if it is the peer of
        a punch in progress: the hello carries that punch's secret id and the
        connection comes from the IP the server named. Anything else is
        closed."""
        keep = False
        try:
            peer_ip = writer.get_extra_info('peername')[0]
            expected = self._expected.get(
                hello[len(PUNCH_HELLO):].decode("utf-8", "replace"))
            if not self._expects(hello, peer_ip):
                print(f"Refusing a punch hello from {safe_text(peer_ip)}: no "
                      f"punch in progress with that id and address")
            else:
                await asyncio.wait_for(write_frame(writer, hello),
                                       PUNCH_HANDSHAKE_TIMEOUT)
                expected[1].set_result((reader, writer))
                keep = True
        except Exception as e:
            print(f"Punch hello failed: {e}")
        finally:
            if not keep:
                await self._close(writer)

    # --- Channels ---

    def _add_channel(self, vip: str, reader, writer) -> Optional[PunchedChannel]:
        if self._stopped or (vip not in self.channels
                             and len(self.channels) >= MAX_PUNCHED_CHANNELS):
            writer.close()
            return None
        abort_on_close(writer.get_extra_info('socket'))
        channel = PunchedChannel(vip, reader, writer, self.handler,
                                 self._channel_closed)
        old = self.channels.get(vip)
        self.channels[vip] = channel
        if old is not None:
            old.close()   # a new punch replaces a channel that was not used
        print(f"Punched a TCP connection to {safe_text(vip)} from port "
              f"{self.local_addr[1]}")
        return channel

    def _channel_closed(self, channel: PunchedChannel):
        if self.channels.get(channel.virtual_ip) is channel:
            del self.channels[channel.virtual_ip]

    @staticmethod
    async def _close(writer):
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    async def stop(self):
        """Cancel the punches under way and close every channel."""
        self._stopped = True
        tasks = list(self._attempts.values()) + list(self._responders)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        channels = list(self.channels.values())
        for channel in channels:
            channel.close()
        await asyncio.gather(*(c.wait_closed() for c in channels),
                             return_exceptions=True)
