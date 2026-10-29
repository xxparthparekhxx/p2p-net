import asyncio
import random
import ipaddress
import json
import base64

class IntroductionServer:
    def __init__(self):
        self.peers = {}
        self.virtual_network = ipaddress.IPv4Network('10.0.0.0/8')
        self.available_ips = set(self.virtual_network.hosts())

    def assign_virtual_ip(self):
        if not self.available_ips:
            raise Exception("No available IPs")
        return str(self.available_ips.pop())

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

async def main():
    intro_server = IntroductionServer()
    await intro_server.start_server('0.0.0.0', 8888)

if __name__ == "__main__":
    main()
