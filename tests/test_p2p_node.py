import asyncio
import socket

import pytest

from kademlia_dht import sha1_hash
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
