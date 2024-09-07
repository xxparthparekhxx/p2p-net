import asyncio
import random
import ipaddress
import json
from cryptography.fernet import Fernet

class IntroductionServer:
    def __init__(self):
        self.peers = {}
        self.virtual_network = ipaddress.IPv4Network('10.0.0.0/8')
        self.available_ips = set(self.virtual_network.hosts())
        self.encryption_key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.encryption_key)

    def assign_virtual_ip(self):
        if not self.available_ips:
            raise Exception("No available IPs")
        return str(self.available_ips.pop())

    def find_nearby_peers(self, public_ip, count=5):
        nearby_peers = random.sample(list(self.peers.items()), min(count, len(self.peers)))
        nearby_peers_info = [{'public_ip': peer[1]['public_ip'], 'port': peer[1]['port']} for peer in nearby_peers]
        return nearby_peers_info

    async def handle_new_peer(self, reader, writer):
        peer_address = writer.get_extra_info('peername')
        print(f"New peer connecting from: {peer_address}")
        
        # Receive the peer's listening address and port
        peer_data = await reader.read(1024)
        peer_info = json.loads(peer_data.decode())
        listening_ip = peer_info['listening_ip']
        listening_port = peer_info['listening_port']
        
        virtual_ip = self.assign_virtual_ip()
        nearby_peers = self.find_nearby_peers(listening_ip)
        
        response = {
            'virtual_ip': virtual_ip,
            'nearby_peers': nearby_peers,
            'encryption_key': self.encryption_key.decode()
        }
        
        print(f"Responding with: {response}")
        json_response = json.dumps(response)
        
        encrypted_response = self.cipher_suite.encrypt(json_response.encode())
        
        writer.write(self.encryption_key)
        await writer.drain()
        
        writer.write(encrypted_response)
        await writer.drain()
        
        self.peers[virtual_ip] = {
            'public_ip': listening_ip,
            'port': listening_port
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
    asyncio.run(main())
