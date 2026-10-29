import asyncio
import os
import random
import json
import base64
from typing import Dict, Optional
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from kademlia_dht import (
    ED25519_PUBLIC_KEY_SIZE,
    KademliaNode,
    Node,
    connect,
    safe_text,
    sha1_hash,
    write_private_file,
)


class IntroductionServerUnreachable(ConnectionError):
    """join_network could not connect to the introduction server."""


def owner_pins_path(key_path: str) -> str:
    """The owner-pin file sits next to the node's key file:
    node_9000.key -> node_9000.owners.json (same directory)."""
    root, _ = os.path.splitext(key_path)
    return root + ".owners.json"


def load_owner_pins(path: str) -> Dict[str, bytes]:
    """Read {domain: owner public key} from `path` ({} if it doesn't exist).

    A file that exists but can't be parsed raises instead of being treated
    as empty: silently dropping the pins would reopen every name to an
    unpinned (majority) lookup.
    """
    try:
        with open(path, "rb") as f:
            raw = json.load(f)
    except FileNotFoundError:
        return {}
    except ValueError as e:
        raise ValueError(f"Owner pin file {path} is not valid JSON ({e}); "
                         f"fix or delete it")
    if not isinstance(raw, dict):
        raise ValueError(f"Owner pin file {path} is not a JSON object")
    pins = {}
    for domain, owner_b64 in raw.items():
        try:
            owner = base64.b64decode(owner_b64, validate=True)
        except (TypeError, ValueError):
            owner = b""
        if len(owner) != ED25519_PUBLIC_KEY_SIZE:
            raise ValueError(f"Owner pin file {path}: entry for "
                             f"{safe_text(domain)} is not a base64 Ed25519 key")
        pins[domain] = owner
    return pins


class P2PNode:
    def __init__(self, ip: str, port: int, key_path: Optional[str] = None):
        self.ip = ip
        self.port = port
        self.id = sha1_hash(f"{ip}:{port}")
        # The signing key persists in key_path (default
        # ~/.p2p-net/node_<port>.key) so this node keeps its names on restart.
        self.kademlia = KademliaNode(self.id, ip, port, key_path=key_path)
        self.virtual_ip = None
        # Client-side owner pins: domain -> owner public key, recorded the
        # first time a name resolves and enforced on every later lookup. They
        # are saved (0600) next to the key file so they survive restarts.
        self.owner_pins_path = owner_pins_path(self.kademlia.key_path)
        self.owner_pins: Dict[str, bytes] = load_owner_pins(self.owner_pins_path)

    def pin_owner(self, domain: str, owner: bytes):
        """Accept only `owner`'s records for `domain` from now on."""
        self.owner_pins[domain] = owner
        self._save_owner_pins()

    def forget_owner(self, domain: str):
        """Drop the pin for `domain`; its next lookup is unpinned again."""
        if self.owner_pins.pop(domain, None) is not None:
            self._save_owner_pins()

    def _save_owner_pins(self):
        data = {domain: base64.b64encode(owner).decode()
                for domain, owner in sorted(self.owner_pins.items())}
        write_private_file(self.owner_pins_path,
                           json.dumps(data, indent=1).encode())

    async def join_network(self, intro_server_address: tuple[str, int]):
        host, port = intro_server_address
        try:
            reader, writer = await connect(host, port)
        except OSError as e:  # refused, unresolvable, or timed out
            raise IntroductionServerUnreachable(
                f"Can't reach the introduction server at {host}:{port} ({e}); "
                f"is it running? Start it with: python introduction_server.py"
            ) from e

        try:
            # Send our listening address and port to the introduction server
            peer_info = {
                'listening_ip': self.ip,
                'listening_port': self.port,
                # Advertise this node's Ed25519 public key so peers can
                # verify records it stores.
                'public_key': base64.b64encode(
                    self.kademlia.signing_key.public_key().public_bytes(
                        Encoding.Raw, PublicFormat.Raw
                    )
                ).decode(),
            }
            writer.write(json.dumps(peer_info).encode())
            await writer.drain()

            # The introduction server no longer ships a plaintext network key.
            # The response is plain JSON: records are authenticated by Ed25519
            # signatures on STORE rather than a shared symmetric key.
            response_data = await reader.read(4096)
            response = json.loads(response_data.decode())

            self.virtual_ip = response['virtual_ip']

            bootstrap_nodes = [
                Node(sha1_hash(f"{peer['public_ip']}:{peer['port']}"),
                     peer['public_ip'],
                     peer['port'],
                     public_key=base64.b64decode(peer['public_key'])
                     if peer.get('public_key') else None)
                for peer in response['nearby_peers']
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
        # Only our own signed record counts as a successful registration.
        stored_value, _ = await self.kademlia.find_value(
            domain_hash, expected_owner=self.kademlia.owner_public_key
        )
        if stored_value == ip:
            print(f"Registration of {domain} succeeded")
        else:
            print(f"Registration of {domain} failed. Expected {ip}, found "
                  f"{safe_text(stored_value)}")
        return stored_value == ip

    async def lookup_domain(self, domain: str,
                            owner: Optional[bytes] = None) -> Optional[str]:
        """Resolve `domain` to its value, or None.

        The first time a name resolves (unpinned: the owner most replicas
        agree on, then its highest seq), that owner's public key is pinned,
        and every later lookup accepts only that owner's records. Pass
        `owner` to pin a known owner for this lookup instead of the saved
        pin; forget_owner() drops a pin.
        """
        domain_hash = sha1_hash(domain)
        pinned = owner if owner is not None else self.owner_pins.get(domain)
        print(f"Looking up domain {domain} (hash: {domain_hash})"
              + (f", owner pinned to {pinned.hex()[:16]}" if pinned else ""))
        record, _ = await self.kademlia.find_record(
            domain_hash, expected_owner=pinned
        )
        result = record.value if record is not None else None
        if record is not None and domain not in self.owner_pins:
            self.pin_owner(domain, record.owner)
        print(f"Lookup result for {domain}: {safe_text(result)}")
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
    join_tasks = [node.join_network(('127.0.0.1', 8888)) for node in nodes]
    try:
        await asyncio.gather(*join_tasks)
    except IntroductionServerUnreachable as e:
        print(f"Error: {e}")
        for task in run_tasks:
            task.cancel()
        await asyncio.gather(*run_tasks, return_exceptions=True)
        return
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
        print(f"Domain {domain} resolves to: "
              f"{safe_text(ip)}")

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