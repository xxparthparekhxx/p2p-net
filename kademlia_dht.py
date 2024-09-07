import asyncio
import random
import json
import hashlib
from typing import List, Tuple, Dict, Optional,Union
from cryptography.fernet import Fernet

K = 20  # k-bucket size
ALPHA = 3  # alpha concurrent network calls
ID_BITS = 160  # SHA-1 hash size

def sha1_hash(data: str) -> int:
    return int(hashlib.sha1(data.encode()).hexdigest(), 16)

class Node:
    def __init__(self, id: int, ip: str, port: int):
        self.id = id
        self.ip = ip
        self.port = port

    def __eq__(self, other):
        return self.id == other.id

    def __hash__(self):
        return hash(self.id)

class KBucket:
    def __init__(self):
        self.nodes: List[Node] = []

    def add(self, node: Node):
        if node in self.nodes:
            self.nodes.remove(node)
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

    async def ping(self, writer):
        writer.write(b"PING")
        await writer.drain()

    async def store(self, writer, key: int, value: str):
        message = f"STOR{key} {value}".encode()
        writer.write(message)
        await writer.drain()

    async def find_node(self, writer, target_id: int):
        message = f"FIND_NODE {target_id}".encode()
        writer.write(message)
        await writer.drain()

    async def find_value(self, writer, key: int):
        message = f"FIND_VALUE {key}".encode()
        writer.write(message)
        await writer.drain()

    async def handle_ping(self, reader, writer):
        writer.write(b"PONG")
        await writer.drain()

    async def handle_store(self, reader, writer):
        data = await reader.read(1024)
        print("storing this data",data)
        key, value = data.decode().split(maxsplit=2)
        self.kademlia_node.data[int(key)] = value
        print(f"Stored key-value pair:{value} {self.kademlia_node.data}")
        writer.write(b"OK")
        await writer.drain()

    async def handle_find_value(self, reader, writer):
        data = await reader.read(1024)
        _, key = data.decode().split()
        key = int(key)
        if key in self.kademlia_node.data:
            response = json.dumps({'value': self.kademlia_node.data[key]})
        else:
            closest_nodes = self.kademlia_node.routing_table.find_closest(key)
            response = json.dumps({'nodes': [{'id': node.id, 'ip': node.ip, 'port': node.port} for node in closest_nodes]})
        writer.write(response.encode())
        await writer.drain()

    async def handle_find_value(self, reader, writer):
        data = await reader.read(1024)
        _, key = data.decode().split()
        key = int(key)
        if key in self.kademlia_node.data:
            response = json.dumps({'value': self.kademlia_node.data[key]})
        else:
            closest_nodes = self.kademlia_node.routing_table.find_closest(key)
            response = json.dumps({'nodes': [{'id': node.id, 'ip': node.ip, 'port': node.port} for node in closest_nodes]})
        writer.write(response.encode())
        await writer.drain()

class KademliaNode:
    def __init__(self, id: int, ip: str, port: int):
        self.id = id
        self.ip = ip
        self.port = port
        self.routing_table = RoutingTable(id)
        self.data: Dict[int, str] = {}
        self.protocol = KademliaProtocol(id, self)

    async def bootstrap(self, bootstrap_nodes: List[Node]):
        for node in bootstrap_nodes:
            await self.ping(node)

    async def ping(self, node: Node):
        try:
            reader, writer = await asyncio.open_connection(node.ip, node.port)
            await self.protocol.ping(writer)
            response = await reader.read(4)
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
                self.data[key] = value
            else:
                store_tasks.append(self._store_on_node(node, key, value))
        await asyncio.gather(*store_tasks)


    async def _store_on_node(self, node: Node, key: int, value: str):
        try:
            reader, writer = await asyncio.open_connection(node.ip, node.port)
            await self.protocol.store(writer, key, value)
            response = await reader.read(1024)
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
            response = await reader.read(1024)
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
            return self.data[key], []
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
                if isinstance(result, str):
                    return result, []
                elif result:
                    nodes.extend(result)
            queried_nodes.update(unqueried)
            nodes = sorted(set(nodes), key=lambda n: n.id ^ key)[:K]
        return None, nodes

    async def _find_value_on_node(self, node: Node, key: int) -> Union[str, List[Node], None]:
        try:
            # print(f"_find_value_on_node  for key {key} on node {node.id} {self.data} ")
            reader, writer = await asyncio.open_connection(node.ip, node.port)
            await self.protocol.find_value(writer, key)
            response = await reader.read(1024)
            writer.close()
            await writer.wait_closed()
            
            # Decode the response and handle potential JSON decoding errors
            try:
                result = json.loads(response.decode())
                if 'value' in result:
                    return result['value']
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
        data = await reader.read(4)
        # print("PROCESSING THIS REQUEST" +data.decode() )
        if data == b"PING":
            await self.protocol.handle_ping(reader, writer)
        elif data == b"STOR":
            await self.protocol.handle_store(reader, writer)
        elif data == b"FIND":
            more_data = await reader.read(5)
            more_data = more_data[1:]
            if more_data == b"NODE":
                print("PROCESSING THIS REQUEST for finding node", more_data)
            if more_data == b"NODE":
                await self.protocol.handle_find_node(reader, writer)
            elif more_data == b"VALU":
                await self.protocol.handle_find_value(reader, writer)
        writer.close()
        await writer.wait_closed()