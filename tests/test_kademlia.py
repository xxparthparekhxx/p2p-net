import asyncio
import base64
import itertools
import json
import os
import socket
import stat
import time

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from kademlia_dht import (
    KademliaNode,
    Node,
    KBucket,
    K,
    RoutingTable,
    CONNECT_TIMEOUT,
    ID_BITS,
    MAX_LOOKUP_QUERIES,
    MAX_MESSAGE_SIZE,
    READ_TIMEOUT,
    STORE_DOMAIN_SEPARATOR,
    VerifiedRecord,
    parse_record_reply,
    record_message,
    verify_record,
)

IP = "127.0.0.1"


# HOME and P2P_NET_KEY_DIR point into tmp_path (autouse fixture in conftest).
_key_files = itertools.count()


def make_node(node_id, ip=IP):
    """A port-0 KademliaNode with a key file of its own under
    $P2P_NET_KEY_DIR (port 0 has no default key path)."""
    key_dir = os.environ["P2P_NET_KEY_DIR"]
    path = os.path.join(key_dir, f"test_node_{next(_key_files)}.key")
    return KademliaNode(node_id, ip, 0, key_path=path)


async def start_node(node):
    """Start a node's RPC server and return it (caller must close it)."""
    server = await asyncio.start_server(node.handle_connection, IP, 0)
    real_port = server.sockets[0].getsockname()[1]
    node.port = real_port
    return server


@pytest.mark.asyncio
async def test_find_node_works():
    """FIND_NODE reaches a peer and returns it from its routing table."""
    node_a = make_node(1)
    node_b = make_node(2)
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
    node_b = make_node(999)
    server_b = await start_node(node_b)
    try:
        # 25 peers known to node_b; a FIND_NODE reply should cap at K=20.
        peers = [Node(i, IP, 10000 + i) for i in range(25)]
        for peer in peers:
            node_b.routing_table.add(peer)

        node_a = make_node(1)
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
    node_b = make_node(998)
    server_b = await start_node(node_b)
    try:
        peers = [Node(i, IP, 20000 + i) for i in range(20)]
        for peer in peers:
            node_b.routing_table.add(peer)

        node_a = make_node(1)
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
    """Seeing a known peer again via the routing table reorders its bucket."""
    our_id = 32
    table = RoutingTable(our_id)
    # 32^36, 32^37 and 32^38 all have bit_length 3, so all three land in the
    # same k-bucket.
    n1 = Node(36, IP, 1)
    n2 = Node(37, IP, 2)
    n3 = Node(38, IP, 3)
    bucket_index = ID_BITS - ((our_id ^ 36).bit_length()) - 1

    table.add(n1)
    table.add(n2)
    table.add(n3)
    assert table.buckets[bucket_index].nodes == [n1, n2, n3]

    # Re-adding n1 keeps the bucket at 3 entries and moves n1 to the tail.
    assert table.add(n1) is True
    assert table.buckets[bucket_index].nodes == [n2, n3, n1]


def make_store_payload(signing_key, key, value, seq=None):
    """Build a signed STOR payload the same way KademliaProtocol.store does.

    Wire format: STOR <key> <seq> <base64 value> <base64 public_key>
                 <base64 signature>  (five space-separated tokens after STOR)
    The signature covers the domain-separated key || seq || value.
    Returns (payload, seq).
    """
    if seq is None:
        seq = time.time_ns()
    public_key_bytes = signing_key.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    value_bytes = value.encode() if isinstance(value, str) else value
    message = (
        STORE_DOMAIN_SEPARATOR
        + str(key).encode()
        + b"\0"
        + str(seq).encode()
        + b"\0"
        + value_bytes
    )
    signature = signing_key.sign(message)
    payload = (
        f"STOR {key} {seq} "
        f"{base64.b64encode(value_bytes).decode()} "
        f"{base64.b64encode(public_key_bytes).decode()} "
        f"{base64.b64encode(signature).decode()}"
    ).encode()
    return payload, seq


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
    node = make_node(1)
    server = await start_node(node)
    owner = Ed25519PrivateKey.generate()
    attacker = Ed25519PrivateKey.generate()
    key = 12345
    owner_key = owner.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    try:
        # The first valid signed STORE binds the name to the signer's key.
        payload, seq1 = make_store_payload(owner, key, "10.0.0.1")
        assert await rpc(node.port, payload) == b"OK"
        assert node.data[key][:3] == (owner_key, seq1, "10.0.0.1")

        # An attacker with a different key is rejected, value unchanged.
        assert await rpc(
            node.port, make_store_payload(attacker, key, "10.0.0.666")[0]
        ) == b"REJECTED"
        assert node.data[key][:3] == (owner_key, seq1, "10.0.0.1")

        # The rightful owner can still update the record with a higher seq.
        payload, seq2 = make_store_payload(owner, key, "10.0.0.2")
        assert seq2 > seq1
        assert await rpc(node.port, payload) == b"OK"
        assert node.data[key][:3] == (owner_key, seq2, "10.0.0.2")

        # Replaying the old signed v1 STORE is rejected; value stays v2.
        assert await rpc(node.port, make_store_payload(owner, key, "10.0.0.1", seq1)[0]) == b"REJECTED"
        assert node.data[key][:3] == (owner_key, seq2, "10.0.0.2")

        # A lower seq with a different value is rejected.
        assert await rpc(
            node.port, make_store_payload(owner, key, "10.0.0.999", seq1)[0]
        ) == b"REJECTED"
        assert node.data[key][:3] == (owner_key, seq2, "10.0.0.2")

        # An equal seq with a different value is rejected.
        assert await rpc(
            node.port, make_store_payload(owner, key, "10.0.0.777", seq2)[0]
        ) == b"REJECTED"
        assert node.data[key][:3] == (owner_key, seq2, "10.0.0.2")

        # An equal seq with the identical value is OK but changes nothing.
        assert await rpc(
            node.port, make_store_payload(owner, key, "10.0.0.2", seq2)[0]
        ) == b"OK"
        assert node.data[key][:3] == (owner_key, seq2, "10.0.0.2")
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_find_value_returns_owner_key():
    """FIND_VALUE replies with the owner public key and seq next to the value."""
    node = make_node(1)
    server = await start_node(node)
    owner = Ed25519PrivateKey.generate()
    key = 54321
    try:
        payload, seq = make_store_payload(owner, key, "10.0.0.7")
        await rpc(node.port, payload)
        reply = await rpc(node.port, f"FIND_VALUE {key}".encode())
        result = json.loads(reply.decode())
        assert result['value'] == "10.0.0.7"
        assert result['seq'] == seq
        expected_owner = owner.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        assert base64.b64decode(result['owner']) == expected_owner
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_store_accepts_values_with_spaces():
    """Regression: values with spaces ("hello world") are stored verbatim."""
    node = make_node(1)
    server = await start_node(node)
    owner = Ed25519PrivateKey.generate()
    key = 777
    try:
        assert await rpc(
            node.port, make_store_payload(owner, key, "hello world")[0]
        ) == b"OK"
        owner_key, seq, value, _ = node.data[key]
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
async def test_store_values_round_trip_exactly():
    """Values of any bytes, including leading/trailing spaces and "", round-trip."""
    node = make_node(1)
    server = await start_node(node)
    owner = Ed25519PrivateKey.generate()
    key = 31337
    try:
        for value in ["  padded  ", "", "a b  c", "x\ty\nz"]:
            payload, _ = make_store_payload(owner, key, value)
            assert await rpc(node.port, payload) == b"OK", value
            assert node.data[key][2] == value, value
            reply = await rpc(node.port, f"FIND_VALUE {key}".encode())
            assert json.loads(reply.decode())['value'] == value, value
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_oversize_length_prefix_closes_connection():
    """A length prefix over the 1 MB cap is rejected, not allocated."""
    node = make_node(1)
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


@pytest.mark.asyncio
async def test_replicated_record_keeps_original_owner_and_seq():
    """A record replicated from node A to node B keeps the original owner and
    seq, and an attacker cannot take over the name on B."""
    node_a = make_node(1)
    node_b = make_node(2)
    server_b = await start_node(node_b)
    attacker = Ed25519PrivateKey.generate()
    key = 4242
    # Node A is the original owner; it signs with its own long-term key.
    owner_key = node_a.owner_public_key
    try:
        # Node A replicates the record to node B directly; this carries node A's
        # signature and seq unchanged (node A is the original owner).
        value = "10.0.0.1"
        seq = time.time_ns()
        await node_a._store_on_node(
            Node(node_b.id, node_b.ip, node_b.port), key, value, seq
        )

        # Node B recorded the original owner and seq, not its own.
        assert key in node_b.data
        owner_b, seq_b, value_b, _ = node_b.data[key]
        assert owner_b == owner_key
        assert seq_b == seq
        assert value_b == value

        # An attacker with a different key cannot take over the name on B.
        assert await rpc(
            node_b.port, make_store_payload(attacker, key, "10.0.0.666")[0]
        ) == b"REJECTED"
        assert node_b.data[key][:3] == (owner_b, seq_b, value)
    finally:
        server_b.close()
        await server_b.wait_closed()


@pytest.mark.asyncio
async def test_short_public_key_is_rejected_not_dropped():
    """A valid-base64 public key that isn't 32 bytes gets REJECTED, and the
    connection stays open instead of being dropped without a reply."""
    node = make_node(1)
    server = await start_node(node)
    owner = Ed25519PrivateKey.generate()
    key = 9090
    try:
        # 31-byte public key: valid base64, wrong length.
        bad_pubkey = bytes(range(31))
        value_bytes = b"some value"
        message = (
            STORE_DOMAIN_SEPARATOR
            + str(key).encode()
            + b"\0"
            + str(time.time_ns()).encode()
            + b"\0"
            + value_bytes
        )
        signature = owner.sign(message)
        seq = time.time_ns()
        payload = (
            f"STOR {key} {seq} "
            f"{base64.b64encode(value_bytes).decode()} "
            f"{base64.b64encode(bad_pubkey).decode()} "
            f"{base64.b64encode(signature).decode()}"
        ).encode()
        assert await rpc(node.port, payload) == b"REJECTED"
        assert node.data == {}

        # The connection is still alive: a PING gets a PONG.
        reader, writer = await asyncio.open_connection(IP, node.port)
        writer.write(len(b"PING").to_bytes(4, "big") + b"PING")
        await writer.drain()
        length = int.from_bytes(await reader.readexactly(4), "big")
        assert await reader.readexactly(length) == b"PONG"
        writer.close()
        await writer.wait_closed()
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_read_timeout_disconnects_stalling_client():
    """A client that declares a length and sends part of the body is
    disconnected within READ_TIMEOUT."""
    import kademlia_dht

    old_timeout = kademlia_dht.READ_TIMEOUT
    kademlia_dht.READ_TIMEOUT = 0.5
    node = make_node(1)
    server = await start_node(node)
    try:
        reader, writer = await asyncio.open_connection(IP, node.port)
        # Declare a 1000-byte body but send only 10 bytes, then stall.
        writer.write((1000).to_bytes(4, "big") + b"1234567890")
        await writer.drain()
        start = time.monotonic()
        data = await reader.read()
        elapsed = time.monotonic() - start
        assert data == b"", "server should close the connection on timeout"
        assert elapsed < 3.0, f"disconnect took {elapsed:.2f}s, too slow"
    finally:
        kademlia_dht.READ_TIMEOUT = old_timeout
        server.close()
        await server.wait_closed()


# --- Read-side verification: FIND_VALUE replies carry the signed record ---


def pub(signing_key):
    return signing_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def b64(data):
    return base64.b64encode(data).decode()


def signed_reply(signer, key, seq, value, owner=None, **overrides):
    """A FIND_VALUE record reply signed by `signer`, claiming `owner`
    (defaults to the signer's own public key)."""
    signature = signer.sign(record_message(key, seq, value.encode()))
    reply = {
        'key': key,
        'seq': seq,
        'value': value,
        'owner': b64(owner if owner is not None else pub(signer)),
        'signature': b64(signature),
    }
    reply.update(overrides)
    return reply


async def start_reply_server(reply: bytes):
    """A fake peer that answers any one framed request with `reply`."""
    async def handle(reader, writer):
        try:
            length = int.from_bytes(await reader.readexactly(4), "big")
            await reader.readexactly(length)
            writer.write(len(reply).to_bytes(4, "big") + reply)
            await writer.drain()
        finally:
            writer.close()

    server = await asyncio.start_server(handle, IP, 0)
    return server, server.sockets[0].getsockname()[1]


async def close_all(servers):
    for server in servers:
        server.close()
    for server in servers:
        await server.wait_closed()


@pytest.mark.asyncio
async def test_store_keeps_one_signature_for_local_copy_and_replicas():
    """KademliaNode.store signs once; the local copy and the replica keep that
    same signature, and FIND_VALUE returns it as a verifiable record."""
    node_a = make_node(1)
    node_b = make_node(2)
    server_a = await start_node(node_a)
    server_b = await start_node(node_b)
    key = 5150
    try:
        # node_a lists itself so store() also writes the local copy.
        node_a.routing_table.add(Node(node_a.id, node_a.ip, node_a.port))
        node_a.routing_table.add(Node(node_b.id, node_b.ip, node_b.port))
        await node_a.store(key, "10.0.0.5")

        local = node_a.data[key]
        replica = node_b.data[key]
        assert local == replica
        owner, seq, value, signature = local
        assert owner == node_a.owner_public_key
        assert verify_record(key, seq, value.encode(), owner, signature)

        reply = json.loads((await rpc(node_b.port, f"FIND_VALUE {key}".encode())).decode())
        assert base64.b64decode(reply['signature']) == signature
        assert reply['key'] == key
        assert parse_record_reply(key, reply) == VerifiedRecord(
            "10.0.0.5", seq, owner, signature
        )
    finally:
        await close_all([server_a, server_b])


@pytest.mark.asyncio
async def test_tampered_record_is_rejected_and_honest_copy_wins():
    """A node whose stored value was changed (old signature kept) sends a
    reply the client rejects; the lookup still finds the genuine value on an
    honest node."""
    key = 1000
    owner = Ed25519PrivateKey.generate()
    honest = make_node(1003)
    tampered = make_node(1001)  # closer to the key than honest
    servers = [await start_node(honest), await start_node(tampered)]
    try:
        payload, seq = make_store_payload(owner, key, "10.0.0.1")
        assert await rpc(honest.port, payload) == b"OK"
        assert await rpc(tampered.port, payload) == b"OK"
        o, s, _, sig = tampered.data[key]
        tampered.data[key] = (o, s, "6.6.6.6", sig)

        tampered_contact = Node(tampered.id, IP, tampered.port)
        honest_contact = Node(honest.id, IP, honest.port)

        client = make_node(7)
        assert await client._find_value_on_node(tampered_contact, key) is None

        # Only the tampered node known: no answer, not the forged value.
        client.routing_table.add(tampered_contact)
        value, _ = await client.find_value(key)
        assert value is None

        # Tampered and honest node known: the genuine value is returned.
        client = make_node(7)
        client.routing_table.add(tampered_contact)
        client.routing_table.add(honest_contact)
        value, _ = await client.find_value(key)
        assert value == "10.0.0.1"

        # The tampered node doing its own lookup ignores its bad local copy.
        tampered.routing_table.add(honest_contact)
        value, _ = await tampered.find_value(key)
        assert value == "10.0.0.1"
    finally:
        await close_all(servers)


@pytest.mark.asyncio
async def test_find_value_reply_with_forged_owner_is_rejected():
    """A reply that names an owner key other than the one that signed it is
    rejected, and expected_owner rejects a record signed by anyone else."""
    key = 2000
    seq = time.time_ns()
    owner = Ed25519PrivateKey.generate()
    attacker = Ed25519PrivateKey.generate()
    forged = [
        # Claims the real owner, signed by the attacker.
        signed_reply(attacker, key, seq, "6.6.6.6", owner=pub(owner)),
        # Real owner's signature, owner field swapped to the attacker's key.
        signed_reply(owner, key, seq, "10.0.0.1", owner=pub(attacker)),
    ]
    servers = []
    try:
        client = make_node(7)
        for reply in forged:
            server, port = await start_reply_server(json.dumps(reply).encode())
            servers.append(server)
            assert await client._find_value_on_node(Node(50, IP, port), key) is None

        # A record the attacker signed with its own key is self-consistent,
        # so it verifies, but not when the caller pins the real owner.
        self_signed = signed_reply(attacker, key, seq, "6.6.6.6")
        server, port = await start_reply_server(json.dumps(self_signed).encode())
        servers.append(server)
        contact = Node(51, IP, port)
        assert await client._find_value_on_node(contact, key) is not None
        assert await client._find_value_on_node(
            contact, key, expected_owner=pub(owner)
        ) is None

        # Lookup over forged peers plus one honest peer returns the honest value.
        genuine = signed_reply(owner, key, seq, "10.0.0.1")
        server, port = await start_reply_server(json.dumps(genuine).encode())
        servers.append(server)
        client = make_node(7)
        for i, srv in enumerate(servers):
            client.routing_table.add(Node(60 + i, IP, srv.sockets[0].getsockname()[1]))
        value, _ = await client.find_value(key, expected_owner=pub(owner))
        assert value == "10.0.0.1"
    finally:
        await close_all(servers)


@pytest.mark.asyncio
async def test_unverifiable_replies_count_as_no_answer():
    """Missing fields, bad base64, wrong-length keys, wrong key, wrong types
    and garbage JSON are each treated as no answer."""
    key = 3000
    seq = time.time_ns()
    owner = Ed25519PrivateKey.generate()
    good = signed_reply(owner, key, seq, "10.0.0.1")
    no_sig = {k: v for k, v in good.items() if k != 'signature'}
    bad_replies = [
        json.dumps(no_sig).encode(),
        json.dumps({**good, 'owner': "not base64!!"}).encode(),
        json.dumps({**good, 'signature': "%%%%"}).encode(),
        json.dumps({**good, 'owner': b64(pub(owner)[:31])}).encode(),
        json.dumps({**good, 'signature': b64(b"\0" * 64)}).encode(),
        json.dumps({**good, 'key': key + 1}).encode(),
        json.dumps({**good, 'seq': str(seq)}).encode(),
        json.dumps({**good, 'seq': True}).encode(),
        json.dumps({**good, 'value': 12345}).encode(),
        json.dumps({**good, 'value': "\ud800"}).encode(),  # lone surrogate
        json.dumps({**good, 'seq': seq + 1}).encode(),
        json.dumps({**good, 'value': "10.0.0.2"}).encode(),
        b"not json",
        b"\xff\xfe",
        b"[" * 100000,  # deeply nested: RecursionError in json
        b'"value"',
        b"[]",
    ]
    servers = []
    try:
        client = make_node(7)
        for reply in bad_replies:
            server, port = await start_reply_server(reply)
            servers.append(server)
            assert await client._find_value_on_node(Node(70, IP, port), key) is None, reply[:60]

        # The unmodified reply verifies.
        server, port = await start_reply_server(json.dumps(good).encode())
        servers.append(server)
        record = await client._find_value_on_node(Node(71, IP, port), key)
        assert record == VerifiedRecord("10.0.0.1", seq, pub(owner),
                                        base64.b64decode(good['signature']))

        # A lookup that hits every bad peer still returns the good record.
        client = make_node(7)
        for i, srv in enumerate(servers):
            client.routing_table.add(Node(100 + i, IP, srv.sockets[0].getsockname()[1]))
        value, _ = await client.find_value(key)
        assert value == "10.0.0.1"
    finally:
        await close_all(servers)


@pytest.mark.asyncio
async def test_find_value_returns_highest_seq():
    """Two verified replies at different seq: the higher seq wins, whichever
    node is closer or answers first."""
    key = 4000
    owner = Ed25519PrivateKey.generate()
    old_payload, seq1 = make_store_payload(owner, key, "10.0.0.1")
    new_payload, seq2 = make_store_payload(owner, key, "10.0.0.2")
    assert seq2 > seq1

    for old_id, new_id in [(4001, 4100), (4100, 4001)]:
        stale = make_node(old_id)
        fresh = make_node(new_id)
        servers = [await start_node(stale), await start_node(fresh)]
        try:
            assert await rpc(stale.port, old_payload) == b"OK"
            assert await rpc(fresh.port, new_payload) == b"OK"
            client = make_node(7)
            client.routing_table.add(Node(stale.id, IP, stale.port))
            client.routing_table.add(Node(fresh.id, IP, fresh.port))
            value, _ = await client.find_value(key)
            assert value == "10.0.0.2"
        finally:
            await close_all(servers)


@pytest.mark.asyncio
async def test_find_value_keeps_searching_after_a_stale_hit():
    """A stale replica answering in the first round does not end the lookup:
    a fresher replica found in a later round wins."""
    key = 5000
    owner = Ed25519PrivateKey.generate()
    old_payload, _ = make_store_payload(owner, key, "10.0.0.1")
    new_payload, _ = make_store_payload(owner, key, "10.0.0.2")
    stale = make_node(5001)
    relay = make_node(5002)   # holds nothing, knows the fresh node
    fresh = make_node(5003)
    servers = [await start_node(n) for n in (stale, relay, fresh)]
    try:
        assert await rpc(stale.port, old_payload) == b"OK"
        assert await rpc(fresh.port, new_payload) == b"OK"
        relay.routing_table.add(Node(fresh.id, IP, fresh.port))
        client = make_node(7)
        client.routing_table.add(Node(stale.id, IP, stale.port))
        client.routing_table.add(Node(relay.id, IP, relay.port))
        value, _ = await client.find_value(key)
        assert value == "10.0.0.2"
    finally:
        await close_all(servers)


@pytest.mark.asyncio
async def test_non_utf8_value_is_rejected_and_server_keeps_serving():
    """A correctly signed STORE whose value isn't UTF-8 gets REJECTED instead
    of dropping the connection, and the node keeps serving."""
    node = make_node(1)
    server = await start_node(node)
    owner = Ed25519PrivateKey.generate()
    key = 6000
    try:
        payload, _ = make_store_payload(owner, key, b"\xff\xfe\x80 not utf-8")
        assert await rpc(node.port, payload) == b"REJECTED"
        assert node.data == {}

        assert await rpc(node.port, b"PING") == b"PONG"
        assert await rpc(node.port, make_store_payload(owner, key, "10.0.0.1")[0]) == b"OK"
        reply = json.loads((await rpc(node.port, f"FIND_VALUE {key}".encode())).decode())
        assert parse_record_reply(key, reply).value == "10.0.0.1"
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_malformed_find_requests_get_an_empty_reply():
    """Malformed FIND_VALUE / FIND_NODE requests get an empty result with no
    unhandled exception, and the next request on a new connection works."""
    loop = asyncio.get_running_loop()
    unhandled = []
    old_handler = loop.get_exception_handler()
    loop.set_exception_handler(lambda _loop, ctx: unhandled.append(ctx))

    node = make_node(1)
    server = await start_node(node)
    owner = Ed25519PrivateKey.generate()
    key = 7000
    bad_args = [b"", b" abc", b" 1 2", b" \xff", b" -1",
                b" " + str(2 ** ID_BITS).encode(),
                b" " + str(2 ** 400).encode()]
    try:
        assert await rpc(node.port, make_store_payload(owner, key, "10.0.0.1")[0]) == b"OK"
        node.routing_table.add(Node(2, IP, 1))
        for arg in bad_args:
            reply = await rpc(node.port, b"FIND_VALUE" + arg)
            assert json.loads(reply.decode()) == {'nodes': []}, arg
            reply = await rpc(node.port, b"FIND_NODE" + arg)
            assert json.loads(reply.decode()) == [], arg

        reply = json.loads((await rpc(node.port, f"FIND_VALUE {key}".encode())).decode())
        assert parse_record_reply(key, reply).value == "10.0.0.1"
        reply = json.loads((await rpc(node.port, b"FIND_NODE 5")).decode())
        assert [n['id'] for n in reply] == [2]
        assert unhandled == []
    finally:
        loop.set_exception_handler(old_handler)
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_bad_node_lists_in_lookup_replies_are_ignored():
    """A peer answering with a malformed node list (string ids, unhashable
    ids, missing fields) counts as no answer instead of crashing the lookup."""
    key = 8000
    owner = Ed25519PrivateKey.generate()
    bad_lists = [
        [{'id': "x", 'ip': IP, 'port': 1}],
        [{'id': [1], 'ip': IP, 'port': 1}],
        [{'id': 1.5, 'ip': IP, 'port': 1}],
        [{'id': 3, 'ip': 7, 'port': 1}],
        [{'id': 3, 'ip': IP, 'port': "1"}],
        [{'id': 3, 'ip': IP}],
        ["not a node"],
        "not a list",
    ]
    honest = make_node(8001)
    servers = [await start_node(honest)]
    try:
        assert await rpc(honest.port, make_store_payload(owner, key, "10.0.0.1")[0]) == b"OK"
        for nodes in bad_lists:
            for request_reply in ({'nodes': nodes}, nodes):
                server, port = await start_reply_server(json.dumps(request_reply).encode())
                servers.append(server)
        client = make_node(7)
        client.routing_table.add(Node(honest.id, IP, honest.port))
        fake_ports = [s.sockets[0].getsockname()[1] for s in servers[1:]]
        for i, port in enumerate(fake_ports[::2]):
            client.routing_table.add(Node(8100 + i, IP, port))
        value, _ = await client.find_value(key)
        assert value == "10.0.0.1"

        client = make_node(7)
        for i, port in enumerate(fake_ports[1::2]):
            client.routing_table.add(Node(8200 + i, IP, port))
        await client.find_node(key)  # must not raise
    finally:
        await close_all(servers)


@pytest.mark.asyncio
async def test_lookup_stops_when_a_peer_hands_out_endless_contacts():
    """A peer that answers every query with 20 fresh, ever-closer contacts
    (all pointing back at itself) cannot keep a lookup running forever."""
    key = 10000
    owner = Ed25519PrivateKey.generate()
    honest = make_node(10003)
    servers = [await start_node(honest)]
    state = {'distance': 2 ** 150, 'queries': 0}

    async def endless(reader, writer):
        try:
            length = int.from_bytes(await reader.readexactly(4), "big")
            request = await reader.readexactly(length)
            state['queries'] += 1
            contacts = []
            for _ in range(K):
                state['distance'] -= 1
                contacts.append({'id': key ^ state['distance'], 'ip': IP, 'port': port})
            body = {'nodes': contacts} if request.startswith(b"FIND_VALUE") else contacts
            reply = json.dumps(body).encode()
            writer.write(len(reply).to_bytes(4, "big") + reply)
            await writer.drain()
        finally:
            writer.close()

    attacker = await asyncio.start_server(endless, IP, 0)
    port = attacker.sockets[0].getsockname()[1]
    servers.append(attacker)
    try:
        assert await rpc(honest.port, make_store_payload(owner, key, "10.0.0.1")[0]) == b"OK"
        client = make_node(7)
        client.routing_table.add(Node(10001, IP, port))
        client.routing_table.add(Node(honest.id, IP, honest.port))

        value, _ = await asyncio.wait_for(client.find_value(key), 10)
        assert value == "10.0.0.1"
        assert state['queries'] < MAX_LOOKUP_QUERIES

        state['queries'] = 0
        result = await asyncio.wait_for(client.find_node(key), 10)
        assert len(result) <= K
        assert state['queries'] < MAX_LOOKUP_QUERIES
    finally:
        await close_all(servers)


# --- Persistent signing key ---


@pytest.mark.asyncio
async def test_restarted_node_with_same_key_file_can_update_its_name(tmp_path):
    """A node restarted with the same key file keeps its identity and can
    still update a name it registered; a node with a new key cannot."""
    key_path = tmp_path / "owner" / "node.key"
    peer = KademliaNode(2, IP, 0, key_path=str(tmp_path / "peer.key"))
    server = await start_node(peer)
    key = 9000
    try:
        owner = KademliaNode(1, IP, 0, key_path=str(key_path))
        assert stat.S_IMODE(os.stat(key_path).st_mode) == 0o600
        owner.routing_table.add(Node(peer.id, IP, peer.port))
        await owner.store(key, "10.0.0.1")
        assert peer.data[key][0] == owner.owner_public_key
        assert peer.data[key][2] == "10.0.0.1"

        # "Restart": a fresh node object loads the same key file.
        restarted = KademliaNode(1, IP, 0, key_path=str(key_path))
        assert restarted.owner_public_key == owner.owner_public_key
        restarted.routing_table.add(Node(peer.id, IP, peer.port))
        await restarted.store(key, "10.0.0.2")
        assert peer.data[key][2] == "10.0.0.2"
        value, _ = await restarted.find_value(
            key, expected_owner=restarted.owner_public_key
        )
        assert value == "10.0.0.2"

        # Without the key file (a new key), the update is refused.
        new_identity = KademliaNode(1, IP, 0, key_path=str(tmp_path / "new.key"))
        assert new_identity.owner_public_key != owner.owner_public_key
        new_identity.routing_table.add(Node(peer.id, IP, peer.port))
        await new_identity.store(key, "10.0.0.3")
        assert peer.data[key][2] == "10.0.0.2"
    finally:
        server.close()
        await server.wait_closed()


def test_key_file_default_location_and_permissions(tmp_path, monkeypatch):
    """Without key_path the key goes to $P2P_NET_KEY_DIR/node_<port>.key, or
    ~/.p2p-net/node_<port>.key if unset; files are 0600, new dirs 0700."""
    node = KademliaNode(1, IP, 4242)
    expected = tmp_path / "keys" / "node_4242.key"
    assert node.key_path == str(expected)
    assert stat.S_IMODE(os.stat(expected).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(expected.parent).st_mode) == 0o700
    assert KademliaNode(1, IP, 4242).owner_public_key == node.owner_public_key

    monkeypatch.delenv("P2P_NET_KEY_DIR")
    node = KademliaNode(1, IP, 4243)
    # HOME is tmp_path/home (see the isolated_key_dir fixture).
    assert node.key_path == str(tmp_path / "home" / ".p2p-net" / "node_4243.key")
    assert os.path.exists(node.key_path)


def test_unreadable_key_file_is_not_replaced(tmp_path):
    """A key file that doesn't hold a valid key raises instead of being
    overwritten with a new key (which would give up every name)."""
    bad = tmp_path / "bad.key"
    bad.write_bytes(b"not a key")
    with pytest.raises(ValueError):
        KademliaNode(1, IP, 0, key_path=str(bad))
    assert bad.read_bytes() == b"not a key"


def test_port_zero_nodes_do_not_share_a_key(tmp_path):
    """Port 0 has no default key file (it used to be one shared node_0.key):
    a port-0 node without key_path is refused, and port-0 nodes with their
    own key_path get distinct keys."""
    with pytest.raises(ValueError, match="key_path"):
        KademliaNode(1, IP, 0)
    assert not (tmp_path / "keys" / "node_0.key").exists()
    assert not (tmp_path / "home" / ".p2p-net" / "node_0.key").exists()

    a = make_node(1)
    b = make_node(2)
    assert a.key_path != b.key_path
    assert a.owner_public_key != b.owner_public_key


@pytest.mark.parametrize("crash_in", ["fsync", "replace"])
def test_interrupted_key_write_leaves_no_file_at_final_path(
        tmp_path, monkeypatch, crash_in):
    """A key write that dies after the temp file is created (during fsync, or
    just before the rename) leaves nothing at the final path, so the next
    start never loads a torn key, and the temp file is cleaned up."""
    key_path = tmp_path / "keys" / "node.key"
    real = getattr(os, crash_in)

    def crash(*args, **kwargs):
        raise OSError(f"simulated crash in os.{crash_in}")

    monkeypatch.setattr(os, crash_in, crash)
    with pytest.raises(OSError, match="simulated crash"):
        KademliaNode(1, IP, 0, key_path=str(key_path))
    assert not key_path.exists()
    assert os.listdir(key_path.parent) == []

    # The next start creates a complete key (0600) at the final path.
    monkeypatch.setattr(os, crash_in, real)
    node = KademliaNode(1, IP, 0, key_path=str(key_path))
    assert stat.S_IMODE(os.stat(key_path).st_mode) == 0o600
    assert os.listdir(key_path.parent) == ["node.key"]
    assert KademliaNode(1, IP, 0, key_path=str(key_path)).owner_public_key \
        == node.owner_public_key


def test_key_write_goes_through_a_private_temp_file(tmp_path, monkeypatch):
    """The key bytes are written to a 0600 temp file in the same directory,
    which is then renamed onto the final path with os.replace."""
    key_path = tmp_path / "keys" / "node.key"
    seen = []
    real_replace = os.replace

    def spy(src, dst):
        seen.append((os.path.dirname(src), stat.S_IMODE(os.stat(src).st_mode),
                     os.path.exists(dst), dst))
        return real_replace(src, dst)

    monkeypatch.setattr(os, "replace", spy)
    KademliaNode(1, IP, 0, key_path=str(key_path))
    assert seen == [(str(key_path.parent), 0o600, False, str(key_path))]


# --- Connect timeout ---


def blackhole_listener():
    """A 127.0.0.1 listener whose accept queue is full and never drained.

    On Linux further SYNs to it are dropped, so a connect() to it hangs (SYN
    retries for about two minutes) instead of being refused: a stand-in for
    an unreachable contact. Returns (port, sockets to close).
    """
    listener = socket.socket()
    listener.bind((IP, 0))
    listener.listen(0)
    port = listener.getsockname()[1]
    sockets = [listener]
    for _ in range(4):
        filler = socket.socket()
        filler.setblocking(False)
        try:
            filler.connect((IP, port))
        except BlockingIOError:
            pass
        sockets.append(filler)
    return port, sockets


def test_connect_timeout_default():
    assert CONNECT_TIMEOUT == 5


@pytest.mark.asyncio
async def test_unreachable_contact_does_not_stall_a_lookup(monkeypatch):
    """A contact whose connect() hangs costs at most CONNECT_TIMEOUT: the
    lookup still returns the honest replica's value right after it, and
    find_node returns too, instead of waiting out the OS connect timeout."""
    import kademlia_dht
    monkeypatch.setattr(kademlia_dht, "CONNECT_TIMEOUT", 0.5)
    key = 11000
    owner = Ed25519PrivateKey.generate()
    honest = make_node(11003)
    server = await start_node(honest)
    dead_port, sockets = blackhole_listener()
    try:
        await asyncio.sleep(0.1)  # let the fillers occupy the accept queue
        # Without the timeout this connect would hang for minutes.
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(kademlia_dht.connect(IP, dead_port), 5)

        assert await rpc(honest.port, make_store_payload(owner, key, "10.0.0.1")[0]) == b"OK"
        client = make_node(7)
        client.routing_table.add(Node(11001, IP, dead_port))  # closest, dead
        client.routing_table.add(Node(honest.id, IP, honest.port))

        start = time.monotonic()
        value, _ = await asyncio.wait_for(client.find_value(key), 10)
        elapsed = time.monotonic() - start
        assert value == "10.0.0.1"
        assert elapsed < 0.5 + 1.0, f"lookup took {elapsed:.2f}s"

        start = time.monotonic()
        await asyncio.wait_for(client.find_node(key), 10)
        assert time.monotonic() - start < 0.5 + 1.0
    finally:
        for sock in sockets:
            sock.close()
        server.close()
        await server.wait_closed()
