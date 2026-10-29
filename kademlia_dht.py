import asyncio
import base64
import json
import hashlib
from typing import List, Tuple, Dict, Optional, Union
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.exceptions import InvalidSignature

K = 20  # k-bucket size
ALPHA = 3  # alpha concurrent network calls
ID_BITS = 160  # SHA-1 hash size

# Every message on the wire is length-prefixed: a 4-byte big-endian length
# followed by exactly that many payload bytes. Replies are read with a loop
# (readexactly) so a full 20-node response can never overflow a fixed buffer.
# The declared length is capped so a peer cannot make us allocate an
# arbitrarily large buffer; larger messages are rejected.
MAX_MESSAGE_SIZE = 1024 * 1024  # 1 MB


def sha1_hash(data: str) -> int:
    return int(hashlib.sha1(data.encode()).hexdigest(), 16)


class Node:
    def __init__(self, id: int, ip: str, port: int, public_key: bytes = None):
        self.id = id
        self.ip = ip
        self.port = port
        self.public_key = public_key

    def __eq__(self, other):
        return self.id == other.id

    def __hash__(self):
        return hash(self.id)


class KBucket:
    def __init__(self):
        self.nodes: List[Node] = []

    def add(self, node: Node):
        # Kademlia least-recently-seen order: seeing a known peer again moves
        # it to the tail of its bucket instead of just dropping it.
        if node in self.nodes:
            self.nodes.remove(node)
            self.nodes.append(node)
        elif len(self.nodes) < K:
            self.nodes.append(node)
        return len(self.nodes) < K


class RoutingTable:
    def __init__(self, our_id: int):
        self.our_id = our_id
        self.buckets = [KBucket() for _ in range(ID_BITS)]

    def add(self, node: Node):
        bucket_index = (ID_BITS - (self.our_id ^ node.id).bit_length() - 1)
        return self.buckets[bucket_index].add(node)

    def find_closest(self, target_id: int) -> List[Node]:
        bucket_index = (ID_BITS - (self.our_id ^ target_id).bit_length() - 1)
        nodes = self.buckets[bucket_index].nodes[:]
        if len(nodes) < K:
            for i in range(1, ID_BITS):
                if bucket_index - i >= 0:
                    nodes.extend(self.buckets[bucket_index - i].nodes)
                if bucket_index + i < ID_BITS:
                    nodes.extend(self.buckets[bucket_index + i].nodes)
                if len(nodes) >= K:
                    break
        return sorted(nodes, key=lambda n: n.id ^ target_id)[:K]


class KademliaProtocol:
    def __init__(self, node_id: int, kademlia_node):
        self.node_id = node_id
        self.kademlia_node = kademlia_node

    async def _send_message(self, writer, data: bytes):
        length = len(data).to_bytes(4, "big")
        writer.write(length + data)
        await writer.drain()

    async def _read_message(self, reader):
        length_bytes = await reader.readexactly(4)
        length = int.from_bytes(length_bytes, "big")
        if length > MAX_MESSAGE_SIZE:
            raise ValueError(
                f"Rejecting {length}-byte message: over the "
                f"{MAX_MESSAGE_SIZE}-byte cap"
            )
        return await reader.readexactly(length)

    async def ping(self, writer):
        await self._send_message(writer, b"PING")

    async def store(self, writer, key: int, value: str):
        # Sign the record with this node's owner key and send the public key
        # and signature so the recipient can verify ownership before storing.
        signing_key = self.kademlia_node.signing_key
        message = f"{key} {value}".encode()
        signature = signing_key.sign(message)
        public_key_bytes = signing_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )

        payload = (
            f"STOR {key} {value} "
            f"{base64.b64encode(public_key_bytes).decode()} "
            f"{base64.b64encode(signature).decode()}"
        ).encode()
        await self._send_message(writer, payload)

    async def find_node(self, writer, target_id: int):
        message = f"FIND_NODE {target_id}".encode()
        await self._send_message(writer, message)

    async def find_value(self, writer, key: int):
        message = f"FIND_VALUE {key}".encode()
        await self._send_message(writer, message)

    async def handle_ping(self, writer):
        await self._send_message(writer, b"PONG")

    async def handle_store(self, writer, payload: bytes):
        # payload: b"STOR <key> <value> <base64 public_key> <base64 signature>"
        # Base64 fields never contain spaces but values can, so split the two
        # trailing fields off the right and keep everything between the key
        # and them as the value (e.g. "hello world").
        try:
            head, public_key_b64, signature_b64 = payload.decode().rsplit(maxsplit=2)
            _, key_s, value = head.split(maxsplit=2)
            key = int(key_s)
        except ValueError:
            print("Rejecting malformed STORE: missing or invalid fields")
            await self._send_message(writer, b"REJECTED")
            return

        try:
            public_key_bytes = base64.b64decode(public_key_b64)
            signature = base64.b64decode(signature_b64)
        except Exception:
            print("Rejecting STORE: bad encoding")
            await self._send_message(writer, b"REJECTED")
            return

        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        message = f"{key} {value}".encode()
        try:
            public_key.verify(signature, message)
        except InvalidSignature:
            print(f"Rejecting STORE: bad signature for key {key}")
            await self._send_message(writer, b"REJECTED")
            return

        # Names are owned on first use: the first valid signed STORE binds the
        # name to the signer's public key. A later STORE signed by a different
        # key is rejected; the rightful owner can keep updating the record.
        record = self.kademlia_node.data.get(key)
        if record is not None and record[0] != public_key_bytes:
            print(f"Rejecting STORE: key {key} is owned by a different key")
            await self._send_message(writer, b"REJECTED")
            return

        self.kademlia_node.data[key] = (public_key_bytes, value)
        print(f"Stored key-value pair: {key} {value}")
        await self._send_message(writer, b"OK")

    async def handle_find_node(self, writer, payload: bytes):
        # payload: b"FIND_NODE <target_id>"
        _, target_s = payload.decode().split()
        target_id = int(target_s)
        closest_nodes = self.kademlia_node.routing_table.find_closest(target_id)
        response = json.dumps(
            [{'id': node.id, 'ip': node.ip, 'port': node.port}
             for node in closest_nodes]
        ).encode()
        await self._send_message(writer, response)

    async def handle_find_value(self, writer, payload: bytes):
        # payload: b"FIND_VALUE <key>"
        _, key_s = payload.decode().split()
        key = int(key_s)
        if key in self.kademlia_node.data:
            # Return the owner public key alongside the value so lookups can
            # verify who owns the name.
            owner, value = self.kademlia_node.data[key]
            response = json.dumps({
                'value': value,
                'owner': base64.b64encode(owner).decode(),
            })
        else:
            closest_nodes = self.kademlia_node.routing_table.find_closest(key)
            response = json.dumps(
                {'nodes': [{'id': node.id, 'ip': node.ip, 'port': node.port}
                           for node in closest_nodes]}
            )
        await self._send_message(writer, response.encode())


class KademliaNode:
    def __init__(self, id: int, ip: str, port: int):
        self.id = id
        self.ip = ip
        self.port = port
        self.routing_table = RoutingTable(id)
        # Maps key -> (owner public key bytes, value). The owner key is the
        # Ed25519 public key of whoever first stored the name (see
        # KademliaProtocol.handle_store).
        self.data: Dict[int, Tuple[bytes, str]] = {}
        # Long-term signing key used to sign records this node stores.
        self.signing_key = Ed25519PrivateKey.generate()
        # This node's own public key, the owner recorded for names it stores.
        self.owner_public_key = self.signing_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        self.protocol = KademliaProtocol(id, self)

    async def bootstrap(self, bootstrap_nodes: List[Node]):
        for node in bootstrap_nodes:
            await self.ping(node)

    async def ping(self, node: Node):
        try:
            reader, writer = await asyncio.open_connection(node.ip, node.port)
            await self.protocol.ping(writer)
            response = await self.protocol._read_message(reader)
            if response == b"PONG":
                self.routing_table.add(node)
                print(f"Successfully pinged and added node {node.id}")
            writer.close()
            await writer.wait_closed()
        except Exception as e:
            print(f"Failed to ping node {node.id} : Tried Pinging {node.ip}:{node.port} : {e}")

    async def store(self, key: int, value: str):
        nodes = self.routing_table.find_closest(key)
        store_tasks = []
        for node in nodes:
            if node.id == self.id:
                # Same ownership rule as handle_store: never take over a name
                # owned by a different key, even in our local cache.
                record = self.data.get(key)
                if record is not None and record[0] != self.owner_public_key:
                    print(f"Refusing to store key {key}: owned by a different key")
                    continue
                self.data[key] = (self.owner_public_key, value)
            else:
                store_tasks.append(self._store_on_node(node, key, value))
        await asyncio.gather(*store_tasks)

    async def _store_on_node(self, node: Node, key: int, value: str):
        try:
            reader, writer = await asyncio.open_connection(node.ip, node.port)
            await self.protocol.store(writer, key, value)
            response = await self.protocol._read_message(reader)
            if response == b"OK":
                print(f"Successfully stored value {value} on node {node.id}")
            else:
                print(f"Failed to store value {value} on node {node.id}: {response.decode()}")
            writer.close()
            await writer.wait_closed()
        except Exception as e:
            print(f"Failed to store key {key} on node {node.id}: {e}")

    async def find_node(self, target_id: int) -> List[Node]:
        nodes = self.routing_table.find_closest(target_id)
        if not nodes:
            return []
        queried_nodes = set()
        while True:
            unqueried = [node for node in nodes if node not in queried_nodes][:ALPHA]
            if not unqueried:
                break
            query_tasks = [self._find_node_on_node(node, target_id) for node in unqueried]
            results = await asyncio.gather(*query_tasks)
            for result in results:
                if result:
                    nodes.extend(result)
            queried_nodes.update(unqueried)
            nodes = sorted(set(nodes), key=lambda n: n.id ^ target_id)[:K]
        return nodes

    async def _find_node_on_node(self, node: Node, target_id: int) -> List[Node]:
        try:
            reader, writer = await asyncio.open_connection(node.ip, node.port)
            await self.protocol.find_node(writer, target_id)
            response = await self.protocol._read_message(reader)
            writer.close()
            await writer.wait_closed()
            nodes_data = json.loads(response.decode())
            return [Node(n['id'], n['ip'], n['port']) for n in nodes_data]
        except Exception as e:
            print(f"Failed to find_node on {node.id}: {e}")
            return []

    async def find_value(self, key: int) -> Tuple[Optional[str], List[Node]]:
        print(f"find_value  for key {key} on node {self.id} {self.data} ")

        if key in self.data:
            owner, value = self.data[key]
            return value, []
        nodes = self.routing_table.find_closest(key)
        if not nodes:
            return None, []
        queried_nodes = set()
        while True:
            unqueried = [node for node in nodes if node not in queried_nodes][:ALPHA]
            if not unqueried:
                break
            query_tasks = [self._find_value_on_node(node, key) for node in unqueried]
            results = await asyncio.gather(*query_tasks)
            for result in results:
                if isinstance(result, tuple):
                    # (value, owner) hit; the owner key is available for
                    # verification but the lookup itself returns the value.
                    return result[0], []
                elif result:
                    nodes.extend(result)
            queried_nodes.update(unqueried)
            nodes = sorted(set(nodes), key=lambda n: n.id ^ key)[:K]
        return None, nodes

    async def _find_value_on_node(
        self, node: Node, key: int
    ) -> Union[Tuple[str, Optional[bytes]], List[Node], None]:
        try:
            reader, writer = await asyncio.open_connection(node.ip, node.port)
            await self.protocol.find_value(writer, key)
            response = await self.protocol._read_message(reader)
            writer.close()
            await writer.wait_closed()

            try:
                result = json.loads(response.decode())
                if 'value' in result:
                    # The owner public key (base64) accompanies stored values.
                    owner = (
                        base64.b64decode(result['owner'])
                        if result.get('owner') else None
                    )
                    return result['value'], owner
                elif 'nodes' in result:
                    return [Node(n['id'], n['ip'], n['port']) for n in result['nodes']]
            except json.JSONDecodeError:
                print(f"Failed to decode JSON from node {node.id}: {response}")
                return None
        except Exception as e:
            print(f"Failed to find_value on {node.id}: {e}")
            return None

    async def listen(self):
        server = await asyncio.start_server(self.handle_connection, self.ip, self.port)
        print(f"Kademlia node listening on {self.ip}:{self.port}")
        async with server:
            await server.serve_forever()

    async def handle_connection(self, reader, writer):
        try:
            data = await self.protocol._read_message(reader)
        except (asyncio.IncompleteReadError, ConnectionResetError,
                BrokenPipeError, OSError, ValueError):
            # ValueError covers messages whose length prefix exceeds the cap.
            writer.close()
            await writer.wait_closed()
            return

        if data == b"PING":
            await self.protocol.handle_ping(writer)
        elif data[:5] == b"STOR ":
            await self.protocol.handle_store(writer, data)
        elif data[:9] == b"FIND_NODE":
            await self.protocol.handle_find_node(writer, data)
        elif data[:10] == b"FIND_VALUE":
            await self.protocol.handle_find_value(writer, data)
        writer.close()
        await writer.wait_closed()
