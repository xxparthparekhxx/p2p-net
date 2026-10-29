import asyncio
import base64
import json

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from kademlia_dht import KademliaNode, Node, KBucket, K, MAX_MESSAGE_SIZE

IP = "127.0.0.1"


async def start_node(node):
    """Start a node's RPC server and return it (caller must close it)."""
    server = await asyncio.start_server(node.handle_connection, IP, 0)
    real_port = server.sockets[0].getsockname()[1]
    node.port = real_port
    return server


@pytest.mark.asyncio
async def test_find_node_works():
    """FIND_NODE reaches a peer and returns it from its routing table."""
    node_a = KademliaNode(1, IP, 0)
    node_b = KademliaNode(2, IP, 0)
    server_a = await start_node(node_a)
    server_b = await start_node(node_b)
    try:
        node_a.routing_table.add(Node(node_b.id, node_b.ip, node_b.port))
        result = await node_a.find_node(node_b.id)
        assert any(n.id == node_b.id for n in result)
    finally:
        server_a.close()
        server_b.close()
        await server_a.wait_closed()
        await server_b.wait_closed()


@pytest.mark.asyncio
async def test_find_node_returns_twenty_nodes():
    """A full 20-node reply over the wire parses into Node objects."""
    target = 12345
    node_b = KademliaNode(999, IP, 0)
    server_b = await start_node(node_b)
    try:
        # 25 peers known to node_b; a FIND_NODE reply should cap at K=20.
        peers = [Node(i, IP, 10000 + i) for i in range(25)]
        for peer in peers:
            node_b.routing_table.add(peer)

        node_a = KademliaNode(1, IP, 0)
        node_a.routing_table.add(Node(node_b.id, node_b.ip, node_b.port))

        result = await node_a.find_node(target)
        assert len(result) == K
        for node in result:
            assert isinstance(node.id, int)
            assert isinstance(node.ip, str)
            assert isinstance(node.port, int)
    finally:
        server_b.close()
        await server_b.wait_closed()


@pytest.mark.asyncio
async def test_find_node_is_length_prefixed():
    """The largest reply (20 nodes) is read fully, not truncated."""
    target = 99999
    node_b = KademliaNode(998, IP, 0)
    server_b = await start_node(node_b)
    try:
        peers = [Node(i, IP, 20000 + i) for i in range(20)]
        for peer in peers:
            node_b.routing_table.add(peer)

        node_a = KademliaNode(1, IP, 0)
        node_a.routing_table.add(Node(node_b.id, node_b.ip, node_b.port))

        result = await node_a.find_node(target)
        assert len(result) == K
        known_ids = {node_b.id} | {p.id for p in peers}
        assert {n.id for n in result} <= known_ids
        for node in result:
            assert isinstance(node.id, int)
            assert isinstance(node.ip, str)
            assert isinstance(node.port, int)
    finally:
        server_b.close()
        await server_b.wait_closed()


def test_bucket_refresh_moves_known_peer_to_tail():
    """Seeing a known peer again moves it to the tail (LRU order)."""
    bucket = KBucket()
    n1 = Node(1, IP, 1)
    n2 = Node(2, IP, 2)
    n3 = Node(3, IP, 3)
    bucket.add(n1)
    bucket.add(n2)
    bucket.add(n3)
    assert bucket.nodes == [n1, n2, n3]

    # Re-adding a known peer keeps bucket size and moves it to the tail.
    assert bucket.add(n1) is True
    assert bucket.nodes == [n2, n3, n1]


def test_routing_table_add_refreshes_bucket():
    bucket_index = 160 - ((1 ^ 2).bit_length()) - 1
    table = KademliaNode(1, IP, 0).routing_table
    n1 = Node(2, IP, 2)
    n2 = Node(3, IP, 3)
    table.add(Node(2, IP, 2))
    table.buckets[bucket_index].nodes = [n1]
    assert table.buckets[bucket_index].add(Node(2, IP, 2)) is True
    assert table.buckets[bucket_index].nodes == [n1]


def make_store_payload(signing_key, key, value):
    """Build a signed STOR payload the same way KademliaProtocol.store does."""
    public_key_bytes = signing_key.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    signature = signing_key.sign(f"{key} {value}".encode())
    return (
        f"STOR {key} {value} "
        f"{base64.b64encode(public_key_bytes).decode()} "
        f"{base64.b64encode(signature).decode()}"
    ).encode()


async def rpc(port, payload):
    """Send one length-prefixed message and read one framed reply."""
    reader, writer = await asyncio.open_connection(IP, port)
    writer.write(len(payload).to_bytes(4, "big") + payload)
    await writer.drain()
    length = int.from_bytes(await reader.readexactly(4), "big")
    response = await reader.readexactly(length)
    writer.close()
    await writer.wait_closed()
    return response


@pytest.mark.asyncio
async def test_store_binds_name_to_first_signer():
    """TOFU ownership: first signed STORE wins, other keys are rejected."""
    node = KademliaNode(1, IP, 0)
    server = await start_node(node)
    owner = Ed25519PrivateKey.generate()
    attacker = Ed25519PrivateKey.generate()
    key = 12345
    try:
        # The first valid signed STORE binds the name to the signer's key.
        assert await rpc(node.port, make_store_payload(owner, key, "10.0.0.1")) == b"OK"
        assert node.data[key] == (
            owner.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
            "10.0.0.1",
        )

        # An attacker with a different key is rejected, value unchanged.
        assert await rpc(
            node.port, make_store_payload(attacker, key, "10.0.0.666")
        ) == b"REJECTED"
        assert node.data[key] == (
            owner.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
            "10.0.0.1",
        )

        # The rightful owner can still update the record.
        assert await rpc(node.port, make_store_payload(owner, key, "10.0.0.2")) == b"OK"
        assert node.data[key] == (
            owner.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
            "10.0.0.2",
        )
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_find_value_returns_owner_key():
    """FIND_VALUE replies with the owner public key next to the value."""
    node = KademliaNode(1, IP, 0)
    server = await start_node(node)
    owner = Ed25519PrivateKey.generate()
    key = 54321
    try:
        await rpc(node.port, make_store_payload(owner, key, "10.0.0.7"))
        reply = await rpc(node.port, f"FIND_VALUE {key}".encode())
        result = json.loads(reply.decode())
        assert result['value'] == "10.0.0.7"
        expected_owner = owner.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        assert base64.b64decode(result['owner']) == expected_owner
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_store_accepts_values_with_spaces():
    """Regression: values with spaces ("hello world") are stored verbatim."""
    node = KademliaNode(1, IP, 0)
    server = await start_node(node)
    owner = Ed25519PrivateKey.generate()
    key = 777
    try:
        assert await rpc(
            node.port, make_store_payload(owner, key, "hello world")
        ) == b"OK"
        owner_key, value = node.data[key]
        assert value == "hello world"
        assert owner_key == owner.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )

        reply = await rpc(node.port, f"FIND_VALUE {key}".encode())
        assert json.loads(reply.decode())['value'] == "hello world"
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_oversize_length_prefix_closes_connection():
    """A length prefix over the 1 MB cap is rejected, not allocated."""
    node = KademliaNode(1, IP, 0)
    server = await start_node(node)
    try:
        reader, writer = await asyncio.open_connection(IP, node.port)
        # Declare a 100 MB message: far over MAX_MESSAGE_SIZE.
        writer.write((100 * 1024 * 1024).to_bytes(4, "big"))
        await writer.drain()
        # The server must hang up instead of allocating a 100 MB buffer.
        assert await reader.read() == b""
        assert node.data == {}
        writer.close()
        await writer.wait_closed()
    finally:
        server.close()
        await server.wait_closed()
