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
    MAX_MESSAGE_SIZE,
    Node,
    parse_node_list,
    read_frame,
    write_frame,
)
from relay import MAX_RELAY_FRAME_SIZE, MAX_RELAYED_MESSAGE_SIZE

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


# --- Relay on the introduction server ---


async def read_json_frame(reader, timeout=10):
    frame = await read_frame(reader, MAX_RELAY_FRAME_SIZE,
                             header_timeout=timeout)
    return json.loads(frame.decode())


class ChannelPeer:
    """A peer's relay channel as the server sees it: registers, then answers
    each 'relayed' frame with handler(payload) -> reply bytes (None: stay
    silent). `received` collects the frames the server forwarded."""

    def __init__(self, port, peer, handler=lambda payload: payload):
        self.port, self.peer, self.handler = port, peer, handler
        self.received = []
        self.ack = None
        self._task = None

    async def open(self, token=None):
        self.reader, self.writer = await asyncio.open_connection(IP, self.port)
        self.writer.write(json.dumps({
            'type': 'relay_register', 'virtual_ip': self.peer['virtual_ip'],
            'token': token or self.peer['relay_token']}).encode())
        await self.writer.drain()
        self.ack = await read_json_frame(self.reader)
        if self.ack['type'] == 'relay_registered':
            self._task = asyncio.create_task(self._serve())
        return self

    async def _serve(self):
        try:
            while True:
                message = await read_json_frame(self.reader, timeout=60)
                if message['type'] != 'relayed':
                    continue
                self.received.append(message)
                reply = self.handler(base64.b64decode(message['payload']))
                if reply is not None:
                    await self.send({'type': 'relay_reply', 'id': message['id'],
                                     'payload': base64.b64encode(reply).decode()})
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass

    async def send(self, message):
        await write_frame(self.writer, json.dumps(message).encode())

    async def close(self):
        if self._task is not None:
            self._task.cancel()
        self.writer.close()
        try:
            await self.writer.wait_closed()
        except Exception:
            pass


async def relay_request(port, peer, to_vip, payload, token=None, from_vip=None):
    """One relay request the way a peer makes it; the frames the server sent
    back: [relay_ready, reply-or-failure], or [failure] if refused up front."""
    reader, writer = await asyncio.open_connection(IP, port)
    try:
        writer.write(json.dumps({
            'type': 'relay', 'from': from_vip or peer['virtual_ip'],
            'token': token or peer['relay_token'], 'to': to_vip}).encode())
        await writer.drain()
        first = await read_json_frame(reader)
        if first['type'] != 'relay_ready':
            return [first]
        await write_frame(writer, payload)
        return [first, await read_json_frame(reader)]
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def relay_setup(count=2):
    """An in-process server and `count` joined (unreachable) peers."""
    server, srv, port = await start_intro()
    peers = [await raw_join(port, IP, dead_port()) for _ in range(count)]
    return server, srv, port, peers


@pytest.mark.asyncio
async def test_join_reply_carries_a_relay_token_only_for_the_joiner(capsys):
    server, srv, port, (a, b) = await relay_setup()
    try:
        assert a['relay_token'] and a['relay_token'] != b['relay_token']
        assert server.peers[a['virtual_ip']]['relay_token'] == a['relay_token']
        # Not in the peer lists handed to others, nor in the server's log.
        assert all('relay_token' not in p for p in b['nearby_peers'])
        assert a['relay_token'] not in capsys.readouterr().out
    finally:
        await close_srv(srv)


@pytest.mark.asyncio
async def test_relay_register_needs_a_joined_peer_and_its_token():
    server, srv, port, (a, b) = await relay_setup()
    try:
        for peer, token in ((a, "wrong"), (a, b['relay_token']),
                            ({'virtual_ip': "10.0.0.99"}, "x")):
            channel = await ChannelPeer(port, peer).open(token=token)
            assert channel.ack['type'] == 'error'
            await channel.close()
        assert server.relay_channels == {}

        good = await ChannelPeer(port, a).open()
        assert good.ack['type'] == 'relay_registered'
        assert list(server.relay_channels) == [a['virtual_ip']]
        await good.close()
    finally:
        await close_srv(srv)


@pytest.mark.asyncio
async def test_relay_round_trip_up_to_the_1mb_cap():
    """A request and its reply of exactly MAX_MESSAGE_SIZE go through
    unchanged, and the forwarded frame names the sender."""
    server, srv, port, (a, b) = await relay_setup()
    channel = await ChannelPeer(
        port, b, handler=lambda payload: payload[::-1]).open()
    try:
        frames = await relay_request(port, a, b['virtual_ip'], b"PING")
        assert [f['type'] for f in frames] == ['relay_ready', 'relay_reply']
        assert base64.b64decode(frames[1]['payload']) == b"GNIP"
        assert channel.received[0]['from'] == a['virtual_ip']

        big = bytes(range(256)) * (MAX_MESSAGE_SIZE // 256)
        assert len(big) == MAX_MESSAGE_SIZE
        frames = await relay_request(port, a, b['virtual_ip'], big)
        assert base64.b64decode(frames[1]['payload']) == big[::-1]
        assert server.pending_relays == {}
    finally:
        await channel.close()
        await close_srv(srv)


@pytest.mark.asyncio
async def test_relay_refuses_a_request_over_the_1mb_cap():
    server, srv, port, (a, b) = await relay_setup()
    channel = await ChannelPeer(port, b).open()
    try:
        reader, writer = await asyncio.open_connection(IP, port)
        writer.write(json.dumps({
            'type': 'relay', 'from': a['virtual_ip'],
            'token': a['relay_token'], 'to': b['virtual_ip']}).encode())
        assert (await read_json_frame(reader))['type'] == 'relay_ready'
        # Only the length prefix of an oversize message: it is refused before
        # any of the body is read.
        writer.write((MAX_RELAYED_MESSAGE_SIZE + 1).to_bytes(4, "big"))
        await writer.drain()
        failure = await read_json_frame(reader)
        assert failure['type'] == 'relay_failed' and 'cap' in failure['error']
        writer.close()
        assert channel.received == []
        assert server.pending_relays == {}
    finally:
        await channel.close()
        await close_srv(srv)


@pytest.mark.asyncio
async def test_relay_refuses_a_reply_over_the_cap_or_malformed():
    server, srv, port, (a, b) = await relay_setup()
    replies = iter([b"x" * (MAX_RELAYED_MESSAGE_SIZE + 1), b"fine"])
    channel = await ChannelPeer(port, b, handler=lambda p: next(replies)).open()
    try:
        frames = await relay_request(port, a, b['virtual_ip'], b"PING")
        assert frames[1]['type'] == 'relay_failed' and 'cap' in frames[1]['error']
        frames = await relay_request(port, a, b['virtual_ip'], b"PING")
        assert frames[1]['type'] == 'relay_reply'

        # A reply that is not base64 never reaches the sender.
        async def garbage(message):
            await channel.send({'type': 'relay_reply', 'id': message['id'],
                                'payload': "not base64 !!"})
        channel.handler = lambda payload: None
        task = asyncio.create_task(
            relay_request(port, a, b['virtual_ip'], b"PING"))
        while len(channel.received) < 3:
            await asyncio.sleep(0.02)
        await garbage(channel.received[-1])
        frames = await task
        assert frames[1]['type'] == 'relay_failed'
        assert 'malformed' in frames[1]['error']
    finally:
        await channel.close()
        await close_srv(srv)


@pytest.mark.asyncio
async def test_relay_only_between_peers_that_joined():
    """Both ends must have joined and the sender must prove it is who it
    claims with its token; nothing reaches the destination otherwise."""
    server, srv, port, (a, b) = await relay_setup()
    channel = await ChannelPeer(port, b).open()
    try:
        cases = [
            dict(from_vip="10.0.0.99", token=a['relay_token']),  # not joined
            dict(from_vip=a['virtual_ip'], token="wrong"),       # no token
            dict(from_vip=a['virtual_ip'], token=b['relay_token']),
            dict(from_vip=["10.0.0.1"], token=a['relay_token']),
        ]
        for case in cases:
            frames = await relay_request(
                port, a, b['virtual_ip'], b"PING", **case)
            assert frames[-1]['type'] == 'relay_failed', case
            assert 'joined' in frames[-1]['error']
        frames = await relay_request(port, a, "10.0.0.99", b"PING")
        assert frames[-1]['type'] == 'relay_failed'
        assert 'joined' in frames[-1]['error']
        assert channel.received == []
    finally:
        await channel.close()
        await close_srv(srv)


@pytest.mark.asyncio
async def test_relay_to_a_peer_without_a_channel_fails_at_once():
    server, srv, port, (a, b) = await relay_setup()
    try:
        frames = await relay_request(port, a, b['virtual_ip'], b"PING")
        assert len(frames) == 1 and frames[0]['type'] == 'relay_failed'
        assert 'no relay channel' in frames[0]['error']
    finally:
        await close_srv(srv)


@pytest.mark.asyncio
async def test_relay_rate_limit_per_sender(monkeypatch):
    monkeypatch.setattr(introduction_server, "RELAY_RATE_LIMIT", 3)
    monkeypatch.setattr(introduction_server, "RELAY_RATE_WINDOW", 60.0)
    server, srv, port, (a, b, c) = await relay_setup(3)
    channel = await ChannelPeer(port, b).open()
    try:
        for _ in range(3):
            frames = await relay_request(port, a, b['virtual_ip'], b"PING")
            assert frames[-1]['type'] == 'relay_reply'
        frames = await relay_request(port, a, b['virtual_ip'], b"PING")
        assert frames[-1]['type'] == 'relay_failed'
        assert 'rate limit' in frames[-1]['error']
        # Another sender has its own budget.
        frames = await relay_request(port, c, b['virtual_ip'], b"PING")
        assert frames[-1]['type'] == 'relay_reply'
    finally:
        await channel.close()
        await close_srv(srv)


@pytest.mark.asyncio
async def test_relay_rate_window_slides(monkeypatch):
    monkeypatch.setattr(introduction_server, "RELAY_RATE_LIMIT", 1)
    monkeypatch.setattr(introduction_server, "RELAY_RATE_WINDOW", 0.3)
    server, srv, port, (a, b) = await relay_setup()
    channel = await ChannelPeer(port, b).open()
    try:
        assert (await relay_request(
            port, a, b['virtual_ip'], b"PING"))[-1]['type'] == 'relay_reply'
        assert (await relay_request(
            port, a, b['virtual_ip'], b"PING"))[-1]['type'] == 'relay_failed'
        await asyncio.sleep(0.4)
        assert (await relay_request(
            port, a, b['virtual_ip'], b"PING"))[-1]['type'] == 'relay_reply'
    finally:
        await channel.close()
        await close_srv(srv)


async def wait_pending(server, count, tries=100):
    for _ in range(tries):
        if len(server.pending_relays) >= count:
            return
        await asyncio.sleep(0.02)
    raise AssertionError(f"{count} relays never became pending")


@pytest.mark.asyncio
@pytest.mark.parametrize("limit, senders, destinations", [
    ("MAX_PENDING_RELAYS_PER_SENDER", 1, 2),
    ("MAX_PENDING_RELAYS_PER_PEER", 2, 1),
    ("MAX_PENDING_RELAYS", 2, 2),
])
async def test_relay_concurrency_limits(monkeypatch, limit, senders,
                                        destinations):
    """Relays waiting for a (silent) peer are capped per sender, per
    destination and in total; the cap refuses the next one right away, and
    the waiting ones still get answered when the peer replies."""
    monkeypatch.setattr(introduction_server, limit, 1)
    server, srv, port, peers = await relay_setup(4)
    a, b, c, d = peers
    # Silent channels, so the first relay stays pending.
    chan_c = await ChannelPeer(port, c, handler=lambda p: None).open()
    chan_d = await ChannelPeer(port, d, handler=lambda p: None).open()
    try:
        first = asyncio.create_task(
            relay_request(port, a, c['virtual_ip'], b"PING"))
        await wait_pending(server, 1)
        # Same sender to another destination / another sender to the same
        # destination / another sender to another destination.
        second_sender, second_dest = {
            "MAX_PENDING_RELAYS_PER_SENDER": (a, d),
            "MAX_PENDING_RELAYS_PER_PEER": (b, c),
            "MAX_PENDING_RELAYS": (b, d),
        }[limit]
        frames = await relay_request(
            port, second_sender, second_dest['virtual_ip'], b"PING")
        assert frames[-1]['type'] == 'relay_failed'
        assert 'too many' in frames[-1]['error']

        # The first is still alive: answer it through the channel.
        message = chan_c.received[0]
        await chan_c.send({'type': 'relay_reply', 'id': message['id'],
                           'payload': base64.b64encode(b"late").decode()})
        frames = await asyncio.wait_for(first, 5)
        assert frames[-1]['type'] == 'relay_reply'
        assert server.pending_relays == {}
    finally:
        await chan_c.close()
        await chan_d.close()
        await close_srv(srv)


@pytest.mark.asyncio
async def test_relay_times_out_when_the_peer_never_replies(monkeypatch):
    monkeypatch.setattr(introduction_server, "RELAY_TIMEOUT", 0.4)
    server, srv, port, (a, b) = await relay_setup()
    channel = await ChannelPeer(port, b, handler=lambda p: None).open()
    try:
        started = asyncio.get_running_loop().time()
        frames = await relay_request(port, a, b['virtual_ip'], b"PING")
        assert asyncio.get_running_loop().time() - started < 3
        assert frames[-1]['type'] == 'relay_failed'
        assert 'no reply' in frames[-1]['error']
        assert server.pending_relays == {}
    finally:
        await channel.close()
        await close_srv(srv)


@pytest.mark.asyncio
async def test_a_stalled_sender_does_not_hold_its_slot(monkeypatch):
    """A sender that gets 'relay_ready' and then never sends the payload is
    cut off by the read timeout and its slot is released."""
    monkeypatch.setattr(kademlia_dht, "READ_TIMEOUT", 0.3)
    server, srv, port, (a, b) = await relay_setup()
    channel = await ChannelPeer(port, b).open()
    try:
        reader, writer = await asyncio.open_connection(IP, port)
        writer.write(json.dumps({
            'type': 'relay', 'from': a['virtual_ip'],
            'token': a['relay_token'], 'to': b['virtual_ip']}).encode())
        assert (await read_json_frame(reader))['type'] == 'relay_ready'
        assert len(server.pending_relays) == 1
        failure = await read_json_frame(reader)  # no payload ever follows
        assert failure['type'] == 'relay_failed'
        assert server.pending_relays == {}
        writer.close()
    finally:
        await channel.close()
        await close_srv(srv)


@pytest.mark.asyncio
async def test_pending_relay_fails_when_the_channel_disconnects():
    server, srv, port, (a, b) = await relay_setup()
    channel = await ChannelPeer(port, b, handler=lambda p: None).open()
    try:
        first = asyncio.create_task(
            relay_request(port, a, b['virtual_ip'], b"PING"))
        await wait_pending(server, 1)
        await channel.close()  # the relayed peer vanishes
        frames = await asyncio.wait_for(first, 5)
        assert frames[-1]['type'] == 'relay_failed'
        assert 'disconnected' in frames[-1]['error']
        assert b['virtual_ip'] not in server.relay_channels
        frames = await relay_request(port, a, b['virtual_ip'], b"PING")
        assert 'no relay channel' in frames[-1]['error']
        assert server.pending_relays == {}
    finally:
        await close_srv(srv)


@pytest.mark.asyncio
async def test_a_new_registration_replaces_the_old_channel():
    server, srv, port, (a, b) = await relay_setup()
    old = await ChannelPeer(port, b, handler=lambda p: None).open()
    try:
        first = asyncio.create_task(
            relay_request(port, a, b['virtual_ip'], b"PING"))
        await wait_pending(server, 1)
        new = await ChannelPeer(port, b, handler=lambda p: b"new").open()
        frames = await asyncio.wait_for(first, 5)  # failed with the old one
        assert frames[-1]['type'] == 'relay_failed'
        frames = await relay_request(port, a, b['virtual_ip'], b"PING")
        assert base64.b64decode(frames[-1]['payload']) == b"new"
        assert old.received and len(new.received) == 1
        await new.close()
    finally:
        await old.close()
        await close_srv(srv)


@pytest.mark.asyncio
async def test_a_peer_cannot_answer_a_relay_meant_for_another(monkeypatch):
    monkeypatch.setattr(introduction_server, "RELAY_TIMEOUT", 0.6)
    server, srv, port, (a, b, c) = await relay_setup(3)
    chan_b = await ChannelPeer(port, b, handler=lambda p: None).open()
    chan_c = await ChannelPeer(port, c, handler=lambda p: None).open()
    try:
        first = asyncio.create_task(
            relay_request(port, a, b['virtual_ip'], b"PING"))
        await wait_pending(server, 1)
        # c answers with the id of the relay that was forwarded to b.
        await chan_c.send({'type': 'relay_reply',
                           'id': chan_b.received[0]['id'],
                           'payload': base64.b64encode(b"forged").decode()})
        frames = await asyncio.wait_for(first, 5)
        assert frames[-1]['type'] == 'relay_failed'
        assert 'no reply' in frames[-1]['error']
    finally:
        await chan_b.close()
        await chan_c.close()
        await close_srv(srv)


@pytest.mark.asyncio
async def test_channel_ping_is_answered_and_garbage_closes_the_channel():
    server, srv, port, (a, b) = await relay_setup()
    channel = await ChannelPeer(port, b).open()
    try:
        await channel.send({'type': 'ping'})
        await channel.send({'type': 'something else'})  # ignored
        await channel.send({'type': 'ping'})
        # (the channel's reader task drops non-relayed frames, so look at the
        # raw connection instead)
        channel._task.cancel()
        pongs = [await read_json_frame(channel.reader) for _ in range(2)]
        assert [m['type'] for m in pongs] == ['pong', 'pong']
        assert b['virtual_ip'] in server.relay_channels

        channel.writer.write((5).to_bytes(4, "big") + b"nojson")
        await channel.writer.drain()
        assert await channel.reader.read() == b""  # the server hung up
        for _ in range(100):
            if b['virtual_ip'] not in server.relay_channels:
                break
            await asyncio.sleep(0.02)
        assert b['virtual_ip'] not in server.relay_channels
    finally:
        await channel.close()
        await close_srv(srv)


@pytest.mark.asyncio
async def test_idle_channel_survives_read_timeout_but_not_idle_timeout(monkeypatch):
    """A registered channel is quiet between requests: the 10 s per-message
    READ_TIMEOUT must not close it. Only RELAY_IDLE_TIMEOUT of silence does,
    and pings postpone that."""
    monkeypatch.setattr(kademlia_dht, "READ_TIMEOUT", 0.15)
    monkeypatch.setattr(introduction_server, "RELAY_IDLE_TIMEOUT", 0.6)
    server, srv, port, (a, b) = await relay_setup()
    channel = await ChannelPeer(port, b).open()
    try:
        await asyncio.sleep(0.3)  # twice READ_TIMEOUT, under the idle timeout
        assert b['virtual_ip'] in server.relay_channels
        for _ in range(5):  # pings keep it open past RELAY_IDLE_TIMEOUT
            await channel.send({'type': 'ping'})
            await asyncio.sleep(0.25)
        assert b['virtual_ip'] in server.relay_channels
        await asyncio.sleep(1.0)  # now stay silent
        assert b['virtual_ip'] not in server.relay_channels
    finally:
        await channel.close()
        await close_srv(srv)


@pytest.mark.asyncio
async def test_a_channel_that_stops_reading_is_dropped(monkeypatch):
    """Writing to a peer's channel is bounded: if its drain never completes
    the relay fails and the channel is aborted instead of piling up."""
    monkeypatch.setattr(introduction_server, "RELAY_WRITE_TIMEOUT", 0.2)
    aborted = []

    class StuckWriter:
        class transport:
            @staticmethod
            def abort():
                aborted.append(True)

        def write(self, data):
            pass

        async def drain(self):
            await asyncio.sleep(60)

    server = IntroductionServer()
    with pytest.raises(ValueError, match="not reading"):
        await server._send_to_channel(StuckWriter(), {'type': 'relayed'})
    assert aborted == [True]


@pytest.mark.asyncio
async def test_releasing_a_virtual_ip_closes_its_channel():
    server, srv, port, (a, b) = await relay_setup()
    channel = await ChannelPeer(port, b).open()
    try:
        server.release_virtual_ip(b['virtual_ip'])
        assert b['virtual_ip'] not in server.relay_channels
        assert await asyncio.wait_for(channel.reader.read(), 5) == b""
    finally:
        await channel.close()
        await close_srv(srv)


@pytest.mark.asyncio
async def test_read_frame_header_timeout_is_separate_from_the_body_timeout(
        monkeypatch):
    """A connection that is legitimately quiet between messages can wait
    longer for the next header; the body of a message is still bounded."""
    monkeypatch.setattr(kademlia_dht, "READ_TIMEOUT", 0.1)
    reader = asyncio.StreamReader()
    with pytest.raises(ValueError, match="header"):
        await read_frame(reader)
    asyncio.get_running_loop().call_later(
        0.3, reader.feed_data, (3).to_bytes(4, "big") + b"abc")
    assert await read_frame(reader, header_timeout=2) == b"abc"

    reader.feed_data((9).to_bytes(4, "big") + b"abc")  # body never completes
    with pytest.raises(ValueError, match="body"):
        await read_frame(reader, header_timeout=2)
