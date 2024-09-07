import asyncio
import random
import json
from cryptography.fernet import Fernet, InvalidToken
from kademlia_dht import KademliaNode, sha1_hash, Node

class P2PNode:
    def __init__(self, ip: str, port: int):
        self.ip = ip
        self.port = port
        self.id = sha1_hash(f"{ip}:{port}")
        self.kademlia = KademliaNode(self.id, ip, port)
        self.virtual_ip = None
        self.cipher_suite = None

    async def join_network(self, intro_server_address: tuple[str, int]):
        try:
            reader, writer = await asyncio.open_connection(*intro_server_address)
            
            # Send our listening address and port to the introduction server
            peer_info = {
                'listening_ip': self.ip,
                'listening_port': self.port
            }
            writer.write(json.dumps(peer_info).encode())
            await writer.drain()
            
            key_data = await reader.read(44)
            fernet_key = key_data.decode()
            if len(fernet_key) != 44:
                raise ValueError(f"Invalid Fernet key length: {len(fernet_key)}")
            
            cipher = Fernet(fernet_key)
            encrypted_message = await reader.read()
            
            decrypted_data = cipher.decrypt(encrypted_message).decode()
            response = json.loads(decrypted_data)
            
            self.virtual_ip = response['virtual_ip']
            self.cipher_suite = Fernet(response['encryption_key'].encode())

            bootstrap_nodes = [
                Node(sha1_hash(f"{peer_info['public_ip']}:{peer_info['port']}"),
                     peer_info['public_ip'], 
                     peer_info['port'])
                for peer_info in response['nearby_peers']
            ]
            
            if bootstrap_nodes:
                await self.kademlia.bootstrap(bootstrap_nodes)
            else:
                print("No bootstrap nodes available")
            
            print(f"Joined network with virtual IP: {self.virtual_ip}")

        except Exception as e:
            print(f"Error while joining the network: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def register_domain(self, domain: str, ip: str):
        domain_hash = sha1_hash(domain)
        print(f"Registering domain {domain} (hash: {domain_hash}) to IP {ip}")
        await self.kademlia.store(domain_hash, ip)
        stored_value, _ = await self.kademlia.find_value(domain_hash)
        if stored_value == ip:
            print(f"Registration of {domain} succeeded")
        else:
            print(f"Registration of {domain} failed. Expected {ip}, found {stored_value}")
        return stored_value == ip

    async def lookup_domain(self, domain: str) -> str:
        domain_hash = sha1_hash(domain)
        print(f"Looking up domain {domain} (hash: {domain_hash})")
        result, _ = await self.kademlia.find_value(domain_hash)
        print(f"Lookup result for {domain}: {result}")
        return result

    async def start(self):
        self.server = await asyncio.start_server(
            self.kademlia.handle_connection, self.ip, self.port
        )
        print(f"P2P node listening on {self.ip}:{self.port}")

    async def run(self):
        async with self.server:
            await self.server.serve_forever()

async def main():
    # Create a network of nodes
    nodes = [P2PNode(f"127.0.0.1", 9000 + i) for i in range(10)]

    # Start all nodes (non-blocking)
    start_tasks = [node.start() for node in nodes]
    await asyncio.gather(*start_tasks)

    # Create tasks for running the nodes
    run_tasks = [asyncio.create_task(node.run()) for node in nodes]

    # Join the network
    join_tasks = [node.join_network(('localhost', 8888)) for node in nodes]
    await asyncio.gather(*join_tasks)
    print("All nodes have joined the network")

    # Wait for the network to stabilize
    await asyncio.sleep(10)

    # Register some domains with detailed verification
    print("Registering domains...")
    success = await nodes[0].register_domain("example.com", "10.0.0.1")
    print(f"Registration of example.com {'succeeded' if success else 'failed'}")
    
    success = await nodes[1].register_domain("test.com", "10.0.0.2")
    print(f"Registration of test.com {'succeeded' if success else 'failed'}")

    # Wait for registrations to propagate
    await asyncio.sleep(5)

    # Lookup domains with better logging
    print("Looking up domains...")
    for domain in ["example.com", "test.com", "nonexistent.com"]:
        ip = await nodes[5].lookup_domain(domain)
        print(f"Domain {domain} resolves to: {ip}")

    # If you want to run indefinitely, you can wait on the run_tasks
    # await asyncio.gather(*run_tasks)

    # Or, if you want to stop after the lookups, you can cancel the tasks
    for task in run_tasks:
        task.cancel()
    
    try:
        await asyncio.gather(*run_tasks)
    except asyncio.CancelledError:
        print("Nodes stopped")

if __name__ == "__main__":
    asyncio.run(main())