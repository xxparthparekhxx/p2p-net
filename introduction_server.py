import argparse
import asyncio
import random
import ipaddress
import json
import base64

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
                'public_ip': peer[1]['public_ip'],
                'port': peer[1]['port'],
                'public_key': base64.b64encode(peer[1]['public_key']).decode()
                if peer[1].get('public_key') else None,
            }
            for peer in nearby_peers
        ]
        return nearby_peers_info

    async def handle_new_peer(self, reader, writer):
        peer_address = writer.get_extra_info('peername')
        print(f"New peer connecting from: {peer_address}")

        # Receive the peer's listening address and port
        peer_data = await reader.read(4096)
        peer_info = json.loads(peer_data.decode())
        listening_ip = peer_info['listening_ip']
        listening_port = peer_info['listening_port']

        public_key_b64 = peer_info.get('public_key')
        public_key_bytes = base64.b64decode(public_key_b64) if public_key_b64 else None

        virtual_ip = self.assign_virtual_ip()
        nearby_peers = self.find_nearby_peers(listening_ip)

        response = {
            'virtual_ip': virtual_ip,
            'nearby_peers': nearby_peers,
        }

        print(f"Responding with: {response}")
        writer.write(json.dumps(response).encode())
        await writer.drain()

        self.peers[virtual_ip] = {
            'public_ip': listening_ip,
            'port': listening_port,
            'public_key': public_key_bytes,
        }

        print(f"New peer joined: {listening_ip}:{listening_port} assigned {virtual_ip}")

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
