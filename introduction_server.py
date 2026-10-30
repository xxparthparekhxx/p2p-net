import argparse
import asyncio
import base64
import ipaddress
import json
import random

from kademlia_dht import READ_TIMEOUT, connect, safe_text

# Loopback by default, so a test run or demo isn't reachable from the
# network. Pass --host 0.0.0.0 (or a LAN address) to accept remote peers.
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8888
VIRTUAL_NETWORK = "10.0.0.0/8"


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
            writer.close()
            await writer.wait_closed()
            return

        kind = request.get('type', 'join')
        if kind == 'join':
            await self._handle_join(writer, request, peer_address)
        else:
            # relay_register / relay are handled in the NAT-traversal relay.
            print(f"Unknown connection type {safe_text(kind)}; dropping it")
            writer.close()
            await writer.wait_closed()

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
        self.peers[virtual_ip] = {
            'public_ip': listening_ip,
            'port': listening_port,
            'observed_ip': observed_ip,
            'observed_port': observed_port,
            'directly_reachable': directly_reachable,
            'public_key': public_key_bytes,
        }

        print(f"Responding with: {response}")
        writer.write(json.dumps(response).encode())
        await writer.drain()

        # The address and port are whatever the peer sent: print their repr
        # so control characters can't reach the operator's terminal.
        print(f"New peer joined: {listening_ip!r} port {listening_port!r} "
              f"assigned {virtual_ip} (observed {observed_ip!r}:"
              f"{observed_port!r}, directly reachable: {directly_reachable})")

        writer.close()
        await writer.wait_closed()

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
