import argparse
import asyncio
import base64
import ipaddress
import json
import random
import secrets
from collections import deque

from kademlia_dht import (
    READ_TIMEOUT,
    connect,
    read_frame,
    safe_text,
    write_frame,
)
from relay import (
    MAX_RELAY_FRAME_SIZE,
    MAX_RELAYED_MESSAGE_SIZE,
    RELAY_IDLE_TIMEOUT,
    RELAY_TIMEOUT,
)

# Loopback by default, so a test run or demo isn't reachable from the
# network. Pass --host 0.0.0.0 (or a LAN address) to accept remote peers.
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8888
VIRTUAL_NETWORK = "10.0.0.0/8"

# Relay (NAT fallback) limits; the protocol itself is described in relay.py.
# Relayed messages in flight (waiting for the peer's reply), per sender, per
# destination and in total. Each holds up to 1 MB in a connection buffer
# (about 3.5 MB while it is base64-encoded and framed for the destination),
# so the total bounds the memory a flood of relays can pin to a few hundred MB.
MAX_PENDING_RELAYS_PER_SENDER = 8
MAX_PENDING_RELAYS_PER_PEER = 16
MAX_PENDING_RELAYS = 64
# Per-sender rate limit: relay requests per virtual ip per window.
RELAY_RATE_LIMIT = 50
RELAY_RATE_WINDOW = 1.0
# Writing to a peer's channel gives up after this long (the peer isn't
# reading), and the channel is dropped.
RELAY_WRITE_TIMEOUT = READ_TIMEOUT


class IntroductionServer:
    def __init__(self, network: str = VIRTUAL_NETWORK):
        self.peers = {}
        self.virtual_network = ipaddress.IPv4Network(network)
        # Addresses are handed out lazily: a counter walks the host range in
        # order, and released addresses are reused first. (Materializing
        # set(network.hosts()) for a /8 is 16.7M objects, over 2 GB.) The
        # host range matches hosts(): no network/broadcast address, except
        # on /31 and /32 where every address is a host.
        net = self.virtual_network
        if net.num_addresses > 2:
            self._first_ip = int(net.network_address) + 1
            self._last_ip = int(net.broadcast_address) - 1
        else:
            self._first_ip = int(net.network_address)
            self._last_ip = int(net.broadcast_address)
        self._next_ip = self._first_ip
        self.released_ips = set()
        # Relay state (NAT fallback): see relay.py.
        self.relay_channels = {}   # virtual ip -> writer of its channel
        self.pending_relays = {}   # relay id -> {'from','to','channel','future'}
        self._relay_times = {}     # virtual ip -> deque of recent request times

    def assign_virtual_ip(self):
        if self.released_ips:
            return str(ipaddress.IPv4Address(self.released_ips.pop()))
        if self._next_ip > self._last_ip:
            raise Exception("No available IPs")
        ip = ipaddress.IPv4Address(self._next_ip)
        self._next_ip += 1
        return str(ip)

    def release_virtual_ip(self, virtual_ip: str):
        """Return an assigned address to the pool and forget its peer."""
        ip = int(ipaddress.IPv4Address(virtual_ip))
        if not self._first_ip <= ip < self._next_ip or ip in self.released_ips:
            raise ValueError(f"{virtual_ip} is not an assigned address")
        self.peers.pop(virtual_ip, None)
        channel = self.relay_channels.pop(virtual_ip, None)
        if channel is not None:
            channel.close()
        self._relay_times.pop(virtual_ip, None)
        self.released_ips.add(ip)

    def find_nearby_peers(self, public_ip, count=5):
        nearby_peers = random.sample(list(self.peers.items()), min(count, len(self.peers)))
        nearby_peers_info = [
            {
                'virtual_ip': virtual_ip,
                'public_ip': peer['public_ip'],
                'port': peer['port'],
                # Whether the server could dial the peer back at its
                # advertised listening address when it joined.
                'reachable': peer.get('directly_reachable', False),
                'public_key': base64.b64encode(peer['public_key']).decode()
                if peer.get('public_key') else None,
            }
            for virtual_ip, peer in nearby_peers
        ]
        return nearby_peers_info

    async def check_directly_reachable(self, ip, port, observed_ip) -> bool:
        """Dial back the peer's advertised listening address (bounded by
        CONNECT_TIMEOUT) to see whether it accepts inbound connections at
        all. A peer behind a NAT that doesn't forward the port is not
        directly reachable and needs the relay instead.

        Only an address on the peer's own IP is dialed. The advertised
        address is whatever the peer sent, and dialing it blindly would let
        any joiner make this server connect to (and learn whether it could
        reach) arbitrary hosts and ports; an advertised IP other than the
        one the peer connected from (e.g. a private LAN address) counts as
        not reachable without a connection attempt.
        """
        try:
            if ipaddress.ip_address(ip) != ipaddress.ip_address(observed_ip):
                return False
        except ValueError:
            return False
        try:
            _reader, writer = await connect(ip, port)
        except Exception:
            return False
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True

    async def handle_new_peer(self, reader, writer):
        peer_address = writer.get_extra_info('peername')
        print(f"New peer connecting from: {peer_address}")

        # The first message on a connection is one unframed JSON object; its
        # "type" picks the flow. No "type" (or "join") is the original join.
        try:
            first = await asyncio.wait_for(reader.read(4096), READ_TIMEOUT)
            request = json.loads(first.decode())
            if not isinstance(request, dict):
                raise ValueError("first message is not a JSON object")
        except Exception as e:
            print(f"Dropping a connection whose first message is malformed: {e}")
            await self._close(writer)
            return

        kind = request.get('type', 'join')
        if kind == 'join':
            await self._handle_join(writer, request, peer_address)
        elif kind == 'relay_register':
            await self._handle_relay_register(reader, writer, request)
        elif kind == 'relay':
            await self._handle_relay(reader, writer, request)
        else:
            print(f"Unknown connection type {safe_text(kind)}; dropping it")
            await self._close(writer)

    async def _handle_join(self, writer, peer_info, peer_address):
        # Receive the peer's listening address and port
        listening_ip = peer_info['listening_ip']
        listening_port = peer_info['listening_port']

        public_key_b64 = peer_info.get('public_key')
        public_key_bytes = base64.b64decode(public_key_b64) if public_key_b64 else None

        # Reflexive address: the address the server actually sees the peer
        # connect from, recorded next to the address the peer reports about
        # itself and sent back to the peer.
        observed_ip, observed_port = peer_address[:2] if peer_address else (None, None)

        virtual_ip = self.assign_virtual_ip()
        # Can the server dial the peer back at its advertised address?
        directly_reachable = await self.check_directly_reachable(
            listening_ip, listening_port, observed_ip)
        nearby_peers = self.find_nearby_peers(listening_ip)

        response = {
            'virtual_ip': virtual_ip,
            'observed_address': {'ip': observed_ip, 'port': observed_port},
            'directly_reachable': directly_reachable,
            'nearby_peers': nearby_peers,
        }

        # The peer is recorded before it hears its virtual ip, so whatever it
        # does next (e.g. open a relay channel) finds itself already joined.
        relay_token = secrets.token_urlsafe(16)
        self.peers[virtual_ip] = {
            'public_ip': listening_ip,
            'port': listening_port,
            'observed_ip': observed_ip,
            'observed_port': observed_port,
            'directly_reachable': directly_reachable,
            'public_key': public_key_bytes,
            'relay_token': relay_token,
        }

        # The relay token is the peer's secret for relay_register / relay
        # requests: it goes to the peer only, never into the log or into the
        # peer lists handed to others.
        print(f"Responding with: {response}")
        response['relay_token'] = relay_token
        writer.write(json.dumps(response).encode())
        await writer.drain()

        # The address and port are whatever the peer sent: print their repr
        # so control characters can't reach the operator's terminal.
        print(f"New peer joined: {listening_ip!r} port {listening_port!r} "
              f"assigned {virtual_ip} (observed {observed_ip!r}:"
              f"{observed_port!r}, directly reachable: {directly_reachable})")

        writer.close()
        await writer.wait_closed()

    @staticmethod
    async def _close(writer):
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    # --- Relay (NAT fallback) ---
    # The protocol is described in relay.py. The server only forwards framed
    # messages between peers that joined; it never interprets them.

    def _is_peer(self, virtual_ip, token) -> bool:
        """Is `virtual_ip` a joined peer, and `token` the secret it got in its
        join reply? (Virtual ips are sequential and public, so the ip alone
        proves nothing.)"""
        peer = self.peers.get(virtual_ip) if isinstance(virtual_ip, str) else None
        return (peer is not None and isinstance(token, str)
                and secrets.compare_digest(token.encode(),
                                           peer['relay_token'].encode()))

    async def _handle_relay_register(self, reader, writer, request):
        """Serve a peer's relay channel until it closes or goes quiet."""
        virtual_ip = request.get('virtual_ip')
        if not self._is_peer(virtual_ip, request.get('token')):
            await write_frame(writer, json.dumps(
                {'type': 'error',
                 'error': 'unknown virtual ip or bad token'}).encode())
            await self._close(writer)
            return

        # One channel per peer: a new registration replaces the old one.
        old = self.relay_channels.get(virtual_ip)
        self.relay_channels[virtual_ip] = writer
        if old is not None:
            old.close()
        print(f"Relay channel registered for {virtual_ip}")

        try:
            await write_frame(writer, json.dumps(
                {'type': 'relay_registered'}).encode())
            while True:
                frame = await read_frame(
                    reader, MAX_RELAY_FRAME_SIZE,
                    header_timeout=RELAY_IDLE_TIMEOUT)
                message = json.loads(frame.decode())
                kind = message.get('type') if isinstance(message, dict) else None
                if kind == 'ping':
                    await write_frame(writer, json.dumps(
                        {'type': 'pong'}).encode())
                elif kind == 'relay_reply':
                    self._complete_relay(writer, message)
                else:
                    print(f"Ignoring a {safe_text(kind)} frame on the relay "
                          f"channel of {virtual_ip}")
        except (asyncio.IncompleteReadError, ConnectionResetError,
                BrokenPipeError, OSError, ValueError, RecursionError) as e:
            # ValueError: an oversize frame, a read timeout (the channel went
            # quiet) or a frame that is not JSON.
            print(f"Relay channel of {virtual_ip} closed: {e}")
        finally:
            if self.relay_channels.get(virtual_ip) is writer:
                del self.relay_channels[virtual_ip]
            self._fail_pending_relays(writer, "the relayed peer disconnected")
            await self._close(writer)

    def _complete_relay(self, channel, message):
        """Hand a relayed peer's reply to the sender waiting on it. Only the
        channel a message was forwarded to can answer it."""
        relay_id = message.get('id')
        pending = self.pending_relays.get(relay_id) if isinstance(
            relay_id, str) else None
        if (pending is None or pending['channel'] is not channel
                or pending['future'].done()):
            return  # unknown, already answered or timed out, or not its to answer
        pending['future'].set_result(message)

    def _fail_pending_relays(self, channel, reason):
        """Fail every relay still waiting on `channel`'s peer."""
        for pending in self.pending_relays.values():
            if pending['channel'] is channel and not pending['future'].done():
                pending['future'].set_result({'error': reason})

    def _check_relay_rate(self, from_vip):
        """Count a relay request against the sender's rate limit (a sliding
        window of recent requests, refused ones included)."""
        now = asyncio.get_running_loop().time()
        times = self._relay_times.setdefault(from_vip, deque())
        while times and now - times[0] > RELAY_RATE_WINDOW:
            times.popleft()
        if len(times) >= RELAY_RATE_LIMIT:
            raise ValueError(f"rate limit: more than {RELAY_RATE_LIMIT} relay "
                             f"requests per {RELAY_RATE_WINDOW}s")
        times.append(now)

    async def _send_to_channel(self, channel, message):
        try:
            await asyncio.wait_for(
                write_frame(channel, json.dumps(message).encode()),
                RELAY_WRITE_TIMEOUT)
        except asyncio.TimeoutError:
            # The peer isn't reading: drop its channel rather than let
            # relays pile up behind it.
            channel.transport.abort()
            raise ValueError("the relayed peer is not reading its channel")

    async def _handle_relay(self, reader, writer, request):
        """Relay one framed message from one joined peer to another and write
        the reply (or why there is none) back as a single frame."""
        try:
            reply = await self._relay_one(reader, writer, request)
        except (asyncio.IncompleteReadError, ConnectionResetError,
                BrokenPipeError, OSError, ValueError) as e:
            reply = {'type': 'relay_failed', 'error': str(e) or type(e).__name__}
        try:
            await write_frame(writer, json.dumps(reply).encode())
        except OSError:
            pass  # the sender went away; nothing to deliver to
        await self._close(writer)

    async def _relay_one(self, reader, writer, request) -> dict:
        """The reply frame for one relay request; raises ValueError (or a
        connection error) with the reason when it can't be relayed. The limits
        are checked before the payload is read, so a refused request costs
        the sender nothing but its header."""
        from_vip, to_vip = request.get('from'), request.get('to')
        if (not self._is_peer(from_vip, request.get('token'))
                or not isinstance(to_vip, str) or to_vip not in self.peers):
            raise ValueError("relay is only between peers that joined")
        self._check_relay_rate(from_vip)
        channel = self.relay_channels.get(to_vip)
        if channel is None:
            raise ValueError(f"{to_vip} has no relay channel")
        pending = list(self.pending_relays.values())
        if sum(p['from'] == from_vip for p in pending) >= MAX_PENDING_RELAYS_PER_SENDER:
            raise ValueError(f"too many relays already waiting from {from_vip}")
        if sum(p['to'] == to_vip for p in pending) >= MAX_PENDING_RELAYS_PER_PEER:
            raise ValueError(f"too many messages already waiting for {to_vip}")
        if len(pending) >= MAX_PENDING_RELAYS:
            raise ValueError("too many relays in flight")

        # The slot is held from here until the reply (or failure) is in.
        relay_id = secrets.token_hex(16)
        future = asyncio.get_running_loop().create_future()
        self.pending_relays[relay_id] = {
            'from': from_vip, 'to': to_vip, 'channel': channel,
            'future': future,
        }
        try:
            await write_frame(writer, json.dumps(
                {'type': 'relay_ready'}).encode())
            payload = await read_frame(reader, MAX_RELAYED_MESSAGE_SIZE)
            if self.relay_channels.get(to_vip) is not channel:
                raise ValueError(f"{to_vip} has no relay channel")
            await self._send_to_channel(channel, {
                'type': 'relayed', 'id': relay_id, 'from': from_vip,
                'payload': base64.b64encode(payload).decode(),
            })
            try:
                message = await asyncio.wait_for(future, RELAY_TIMEOUT)
            except asyncio.TimeoutError:
                raise ValueError(f"no reply within {RELAY_TIMEOUT}s")
        finally:
            del self.pending_relays[relay_id]

        if 'error' in message:
            # The relayed peer's own words: bounded, they go to the sender.
            raise ValueError(str(message['error'])[:200])
        try:
            reply = base64.b64decode(message.get('payload'), validate=True)
        except (TypeError, ValueError):
            raise ValueError("the relayed peer sent a malformed reply")
        if len(reply) > MAX_RELAYED_MESSAGE_SIZE:
            raise ValueError(f"the relayed reply is over the "
                             f"{MAX_RELAYED_MESSAGE_SIZE}-byte cap")
        return {'type': 'relay_reply', 'payload': message['payload']}

    async def start_server(self, host, port):
        server = await asyncio.start_server(
            self.handle_new_peer, host, port)

        addr = server.sockets[0].getsockname()
        print(f'Introduction server serving on {addr}')

        async with server:
            await server.serve_forever()

def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="p2p-net introduction (bootstrap) server")
    parser.add_argument(
        "--host", default=DEFAULT_HOST,
        help=f"address to listen on (default {DEFAULT_HOST}, local only; "
             f"use 0.0.0.0 to accept peers from other machines)")
    parser.add_argument(
        "--port", type=int, default=DEFAULT_PORT,
        help=f"port to listen on (default {DEFAULT_PORT}; 0 picks a free port)")
    return parser.parse_args(argv)


async def main(argv=None):
    args = parse_args(argv)
    intro_server = IntroductionServer()
    await intro_server.start_server(args.host, args.port)

if __name__ == "__main__":
    asyncio.run(main())
