import asyncio
import base64
import json
import socket

import pytest

import introduction_server
import kademlia_dht
from introduction_server import IntroductionServer
from kademlia_dht import (
    KademliaNode,
    Node,
    parse_node_list,
    read_frame,
    write_frame,
)

IP = "127.0.0.1"


def dead_port():
    """A 127.0.0.1 port nothing listens on (bound, then released)."""
    with socket.socket() as s:
        s.bind((IP, 0))
        return s.getsockname()[1]


async def start_intro(server=None):
    """Start an IntroductionServer in-process; returns (server, srv, port)."""
    server = server if server is not None else IntroductionServer()
    srv = await asyncio.start_server(server.handle_new_peer, IP, 0)
    return server, srv, srv.sockets[0].getsockname()[1]


async def close_srv(srv):
    srv.close()
    await srv.wait_closed()


async def raw_join(port, listening_ip, listening_port, public_key=None):
    """Join the way a peer does: one unframed JSON hello, one JSON reply."""
    reader, writer = await asyncio.open_connection(IP, port)
    info = {'listening_ip': listening_ip, 'listening_port': listening_port}
    if public_key is not None:
        info['public_key'] = base64.b64encode(public_key).decode()
    writer.write(json.dumps(info).encode())
    await writer.drain()
    response = json.loads(
        (await asyncio.wait_for(reader.read(4096), 10)).decode())
    writer.close()
    await writer.wait_closed()
    return response


@pytest.mark.asyncio
async def test_join_reports_the_observed_reflexive_address():
    """The server records the address it actually sees the peer connect from
    (the socket's peername), next to the address the peer reports, and tells
    the peer its observed public address in the join reply."""
    server, srv, port = await start_intro()
    try:
        # Advertise an address that isn't the one the peer connected from: it
        # is recorded as reported, and not dialed (see the dial-back test).
        advertised_port = dead_port()
        response = await raw_join(port, "192.0.2.1", advertised_port)
        assert response['observed_address']['ip'] == IP
        assert response['observed_address']['port'] > 0
        assert response['directly_reachable'] is False
        entry = server.peers[response['virtual_ip']]
        assert entry['observed_ip'] == IP
        assert entry['observed_port'] == response['observed_address']['port']
        # The reported address is kept alongside, unmodified.
        assert entry['public_ip'] == "192.0.2.1"
        assert entry['port'] == advertised_port
    finally:
        await close_srv(srv)


@pytest.mark.asyncio
async def test_reachability_check_marks_live_and_dead_listeners():
    """A peer whose advertised listening port accepts connections is marked
    directly reachable; a peer advertising a port nothing listens on is
    not, and both flags are recorded on the server's peer entry."""
    server, srv, port = await start_intro()
    live = await asyncio.start_server(lambda r, w: None, IP, 0)
    live_port = live.sockets[0].getsockname()[1]
    try:
        reachable = await raw_join(port, IP, live_port)
        assert reachable['directly_reachable'] is True
        assert server.peers[reachable['virtual_ip']]['directly_reachable'] is True

        unreachable = await raw_join(port, IP, dead_port())
        assert unreachable['directly_reachable'] is False
        assert server.peers[unreachable['virtual_ip']]['directly_reachable'] is False
    finally:
        live.close()
        await live.wait_closed()
        await close_srv(srv)


@pytest.mark.asyncio
async def test_reachability_probe_is_bounded_by_connect_timeout(monkeypatch):
    """A peer advertising an address that drops SYNs (a blackhole, the
    stand-in for a NAT that silently discards inbound connections) costs at
    most CONNECT_TIMEOUT, not the OS's two-minute SYN retry."""
    monkeypatch.setattr(kademlia_dht, "CONNECT_TIMEOUT", 0.5)
    server, srv, port = await start_intro()
    listener = socket.socket()
    listener.bind((IP, 0))
    listener.listen(0)
    blackhole = listener.getsockname()[1]
    fillers = []
    for _ in range(4):
        filler = socket.socket()
        filler.setblocking(False)
        try:
            filler.connect((IP, blackhole))
        except BlockingIOError:
            pass
        fillers.append(filler)
    try:
        await asyncio.sleep(0.1)  # let the fillers occupy the accept queue
        response = await asyncio.wait_for(
            raw_join(port, IP, blackhole), 5)
        assert response['directly_reachable'] is False
    finally:
        for sock in [listener] + fillers:
            sock.close()
        await close_srv(srv)


@pytest.mark.asyncio
async def test_dial_back_only_dials_the_peers_own_ip(monkeypatch):
    """The advertised address is peer-supplied, so the server dials it only
    when its IP is the one the peer connected from: a joiner cannot make the
    server connect to arbitrary hosts and ports (or learn whether they are
    open)."""
    dialed = []

    async def spy_connect(ip, port):
        dialed.append((ip, port))
        raise ConnectionRefusedError

    monkeypatch.setattr(introduction_server, "connect", spy_connect)
    server, srv, port = await start_intro()
    try:
        for other in ("192.0.2.1", "10.1.2.3", "not an address", 7):
            response = await raw_join(port, other, 9)
            assert response['directly_reachable'] is False
        assert dialed == []

        await raw_join(port, IP, 4321)  # same IP as the connection: dialed
        assert dialed == [(IP, 4321)]
    finally:
        await close_srv(srv)


@pytest.mark.asyncio
async def test_peer_is_recorded_before_it_hears_its_virtual_ip():
    """The join reply is written only after the peer is in server.peers, so
    a peer that acts on its virtual ip at once is already joined."""
    server = IntroductionServer()
    seen = []

    class FakeWriter:
        def get_extra_info(self, name):
            return (IP, 5555)

        def write(self, data):
            seen.append(json.loads(data.decode())['virtual_ip'] in server.peers)

        async def drain(self):
            pass

        def close(self):
            pass

        async def wait_closed(self):
            pass

    await server._handle_join(
        FakeWriter(), {'listening_ip': IP, 'listening_port': dead_port()},
        (IP, 5555))
    assert seen == [True]


@pytest.mark.asyncio
async def test_nearby_peers_carry_reachable_flag_and_virtual_ip():
    """Peers handed out in the join reply carry the reachability flag and
    their virtual ip, so the joining peer knows whom to reach via relay."""
    server, srv, port = await start_intro()
    live = await asyncio.start_server(lambda r, w: None, IP, 0)
    live_port = live.sockets[0].getsockname()[1]
    try:
        dead = await raw_join(port, IP, dead_port())
        alive = await raw_join(port, IP, live_port)
        third = await raw_join(port, IP, dead_port())
        nearby = {p['virtual_ip']: p for p in third['nearby_peers']}
        assert nearby[dead['virtual_ip']]['reachable'] is False
        assert nearby[alive['virtual_ip']]['reachable'] is True
        assert nearby[dead['virtual_ip']]['public_ip'] == IP
        assert isinstance(nearby[dead['virtual_ip']]['port'], int)
    finally:
        live.close()
        await live.wait_closed()
        await close_srv(srv)


@pytest.mark.asyncio
async def test_contact_lists_carry_reachable_and_virtual_ip():
    """FIND_NODE / FIND_VALUE node lists include the NAT fields when the
    contact knows them, and parse_node_list keeps them on the Node."""
    import os
    key_dir = os.environ["P2P_NET_KEY_DIR"]
    node = KademliaNode(1, IP, 0, key_path=os.path.join(key_dir, "t_nat.key"))
    server = await asyncio.start_server(node.handle_connection, IP, 0)
    port = server.sockets[0].getsockname()[1]
    try:
        peer = Node(2, IP, 1234, reachable=False, virtual_ip="10.0.0.9")
        node.routing_table.add(peer)

        async def rpc(payload):
            reader, writer = await asyncio.open_connection(IP, port)
            await write_frame(writer, payload)
            reply = await read_frame(reader)
            writer.close()
            await writer.wait_closed()
            return reply

        reply = json.loads((await rpc(b"FIND_NODE 5")).decode())
        assert reply == [{'id': 2, 'ip': IP, 'port': 1234,
                          'reachable': False, 'virtual_ip': "10.0.0.9"}]
        parsed = parse_node_list(reply)
        assert parsed[0].reachable is False
        assert parsed[0].virtual_ip == "10.0.0.9"

        reply = json.loads((await rpc(b"FIND_VALUE 5")).decode())
        assert reply == {'nodes': [{'id': 2, 'ip': IP, 'port': 1234,
                                    'reachable': False,
                                    'virtual_ip': "10.0.0.9"}]}

        # A contact without NAT metadata still serializes the plain fields.
        node.routing_table.add(Node(3, IP, 4321))
        reply = json.loads((await rpc(b"FIND_NODE 5")).decode())
        assert {'id': 3, 'ip': IP, 'port': 4321} in reply

        # Garbage NAT fields in a reply are rejected like the other fields.
        for bad in ({'id': 4, 'ip': IP, 'port': 1, 'reachable': "yes"},
                    {'id': 4, 'ip': IP, 'port': 1, 'virtual_ip': 7}):
            with pytest.raises(ValueError):
                parse_node_list([bad])
    finally:
        server.close()
        await server.wait_closed()
