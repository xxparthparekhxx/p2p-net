import asyncio
import base64
import json
import os
import socket
import stat

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from kademlia_dht import KademliaNode, Node, record_message, sha1_hash
from p2p_node import IntroductionServerUnreachable, P2PNode

IP = "127.0.0.1"


def dead_port():
    """A 127.0.0.1 port nothing listens on (bound, then released)."""
    with socket.socket() as s:
        s.bind((IP, 0))
        return s.getsockname()[1]


@pytest.mark.asyncio
async def test_join_network_against_dead_port_raises_clear_error(tmp_path):
    """No introduction server: join_network raises a ConnectionError that
    names the address, instead of UnboundLocalError from its finally."""
    node = P2PNode(IP, 0, key_path=str(tmp_path / "node.key"))
    port = dead_port()
    with pytest.raises(IntroductionServerUnreachable,
                       match=f"introduction server at {IP}:{port}") as info:
        await asyncio.wait_for(node.join_network((IP, port)), 10)
    assert isinstance(info.value, ConnectionError)
    assert node.virtual_ip is None


@pytest.mark.asyncio
async def test_lookup_prints_resolved_value_safely(tmp_path, capsys):
    """A resolved value full of terminal escapes is printed escaped."""
    node = P2PNode(IP, 0, key_path=str(tmp_path / "node.key"))
    evil = "\x1b]0;pwned\x07\x1b[2J" + "A" * 500
    await node.kademlia.store(sha1_hash("evil.test"), evil)  # local copy
    assert await node.lookup_domain("evil.test") == evil
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\x07" not in out
    assert "Lookup result for evil.test: '\\x1b]0;pwned\\x07" in out


# --- Owner pins ---


def _pub(signing_key):
    return signing_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


async def _serve(node):
    server = await asyncio.start_server(node.handle_connection, IP, 0)
    node.port = server.sockets[0].getsockname()[1]
    return server


async def _serve_record(signer, key, seq, value):
    """A fake replica answering every FIND_VALUE with `signer`'s own validly
    signed record (a malicious node holding a record of its own)."""
    signature = signer.sign(record_message(key, seq, value.encode()))
    reply = json.dumps({
        'key': key, 'seq': seq,
        'value': base64.b64encode(value.encode()).decode(),
        'owner': base64.b64encode(_pub(signer)).decode(),
        'signature': base64.b64encode(signature).decode(),
    }).encode()

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


@pytest.mark.asyncio
async def test_honest_owner_wins_and_next_lookup_is_pinned(tmp_path):
    """One malicious node with its own record at seq 2**64-1 vs two honest
    replicas: the honest owner wins the first lookup and is pinned (saved,
    0600, next to the key file). Later lookups, including after a restart,
    stay on the honest owner even once the attacker serves a majority."""
    domain = "example.com"
    key = sha1_hash(domain)
    attacker = Ed25519PrivateKey.generate()
    owner = KademliaNode(1, IP, 0, key_path=str(tmp_path / "owner.key"))
    replicas = [KademliaNode(i, IP, 0, key_path=str(tmp_path / f"r{i}.key"))
                for i in (2, 3)]
    servers = [await _serve(n) for n in replicas]
    try:
        for n in replicas:
            owner.routing_table.add(Node(n.id, IP, n.port))
        await owner.store(key, "10.0.0.1")
        assert all(n.data[key][2] == "10.0.0.1" for n in replicas)

        evil, evil_port = await _serve_record(attacker, key, 2 ** 64 - 1, "6.6.6.6")
        servers.append(evil)

        client_key = str(tmp_path / "client" / "node_7000.key")
        client = P2PNode(IP, 7000, key_path=client_key)
        client.kademlia.routing_table.add(Node(key ^ 1, IP, evil_port))
        for n in replicas:
            client.kademlia.routing_table.add(Node(n.id, IP, n.port))

        assert await client.lookup_domain(domain) == "10.0.0.1"
        assert client.owner_pins == {domain: owner.owner_public_key}
        pins_file = tmp_path / "client" / "node_7000.owners.json"
        assert client.owner_pins_path == str(pins_file)
        assert stat.S_IMODE(os.stat(pins_file).st_mode) == 0o600
        assert json.loads(pins_file.read_text()) == {
            domain: base64.b64encode(owner.owner_public_key).decode()}

        # The attacker now serves from three more endpoints: 4 vs 2.
        for _ in range(3):
            server, port = await _serve_record(attacker, key, 2 ** 64 - 1, "6.6.6.6")
            servers.append(server)
            client.kademlia.routing_table.add(Node(key ^ port, IP, port))
        contacts = [c for b in client.kademlia.routing_table.buckets for c in b.nodes]

        # Pinned: still the honest owner.
        assert await client.lookup_domain(domain) == "10.0.0.1"

        # Restarted with the same key path: the pin is loaded from disk.
        restarted = P2PNode(IP, 7000, key_path=client_key)
        assert restarted.owner_pins == {domain: owner.owner_public_key}
        for c in contacts:
            restarted.kademlia.routing_table.add(c)
        assert await restarted.lookup_domain(domain) == "10.0.0.1"

        # A client with no pin follows the (now attacker) majority: the pin
        # is what protects later lookups.
        fresh = P2PNode(IP, 7001, key_path=str(tmp_path / "fresh" / "node.key"))
        for c in contacts:
            fresh.kademlia.routing_table.add(c)
        assert await fresh.lookup_domain(domain) == "6.6.6.6"

        # forget_owner drops the pin (and the saved entry).
        restarted.forget_owner(domain)
        assert json.loads(pins_file.read_text()) == {}
    finally:
        for server in servers:
            server.close()
        for server in servers:
            await server.wait_closed()


def test_corrupt_owner_pin_file_raises(tmp_path):
    """A pin file that can't be read raises instead of silently unpinning."""
    key_path = tmp_path / "node.key"
    pins = tmp_path / "node.owners.json"
    for bad in (b"{not json", b"[]", b'{"a.com": "short"}'):
        pins.write_bytes(bad)
        with pytest.raises(ValueError, match="Owner pin file"):
            P2PNode(IP, 0, key_path=str(key_path))
