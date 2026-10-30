"""TCP hole punching tests.

No real NAT is involved, and none of this shows a punch works through one.
A NAT that drops unsolicited inbound SYNs is stood in for by a Firewall: a
listening socket on the node's port whose accept queue is full, so the kernel
silently drops every SYN that does not belong to a connection the node itself
started. That is the behaviour a punch relies on, and with it the nodes really
do a TCP simultaneous open on loopback (each side's SYN is dropped until the
other side's connect() is under way). What it leaves out: address and port
translation, mapping timeouts, NATs that answer an unsolicited SYN with a
RST, and anything about real routers.

The introduction server, the relay and the nodes are the real code, talking
over loopback TCP.
"""

import asyncio
import json
import socket

import pytest

import introduction_server
import kademlia_dht
import p2p_node as p2p_node_module
import punch
import stun
from kademlia_dht import KademliaNode, Node, PUNCH_HELLO, read_frame, write_frame
from p2p_node import P2PNode
from punch import PunchClient, PunchedChannel
from relay import RelayClient
from test_nat_traversal import (
    IP,
    close_srv,
    dead_port,
    raw_join,
    read_json_frame,
    scripted_server,
    start_intro,
    wait_until,
)
from test_stun import FakeTcpServer, tcp_report_source, tcp_shifted


@pytest.fixture(autouse=True)
def short_connect_timeout(monkeypatch):
    """A dial to a Firewall is dropped, not refused: keep the wait short."""
    monkeypatch.setattr(kademlia_dht, "CONNECT_TIMEOUT", 0.3)


class Firewall:
    """Stands in for a NAT that drops unsolicited inbound SYNs (see the top of
    this file): a listener on the node's port with a full accept queue.
    Sockets that connect *out* from the same port are not affected."""

    def __init__(self):
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self.listener.bind((IP, 0))
        self.listener.listen(0)
        self.port = self.listener.getsockname()[1]
        self.fillers = []
        for _ in range(3):
            filler = socket.socket()
            filler.setblocking(False)
            try:
                filler.connect((IP, self.port))
            except BlockingIOError:
                pass
            self.fillers.append(filler)

    def close(self):
        for sock in [self.listener] + self.fillers:
            sock.close()


# --- The introduction server's side, with raw clients ---


class PunchChannel:
    """A peer's relay channel as the server sees it, registered as taking part
    in hole punching (or not). Keeps every frame the server sends; the
    punch_go frames are also queued."""

    def __init__(self, port, peer, punch_flag=True, extra=None):
        self.port, self.peer, self.punch_flag = port, peer, punch_flag
        self.extra = extra or {}
        self.messages = []
        self.gos = asyncio.Queue()
        self.ack = None
        self._task = None

    async def open(self):
        self.reader, self.writer = await asyncio.open_connection(IP, self.port)
        register = {'type': 'relay_register',
                    'virtual_ip': self.peer['virtual_ip'],
                    'token': self.peer['relay_token']}
        if self.punch_flag is not False:
            register['punch'] = self.punch_flag
        register.update(self.extra)
        self.writer.write(json.dumps(register).encode())
        await self.writer.drain()
        self.ack = await read_json_frame(self.reader)
        if self.ack['type'] == 'relay_registered':
            self._task = asyncio.create_task(self._serve())
        return self

    @property
    def endpoint(self):
        """Where the server sees this channel come from."""
        return {'ip': IP, 'port': self.writer.get_extra_info('sockname')[1]}

    async def _serve(self):
        try:
            while True:
                message = await read_json_frame(self.reader, timeout=60)
                self.messages.append(message)
                if message['type'] == 'punch_go':
                    self.gos.put_nowait(message)
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass

    async def next_go(self, timeout=5):
        return await asyncio.wait_for(self.gos.get(), timeout)

    async def close(self):
        if self._task is not None:
            self._task.cancel()
        self.writer.close()
        try:
            await self.writer.wait_closed()
        except Exception:
            pass


async def send_first(port, message):
    """Open a connection to the server and send its first (unframed) message."""
    reader, writer = await asyncio.open_connection(IP, port)
    writer.write(json.dumps(message).encode())
    await writer.drain()
    return reader, writer


async def start_punch(server_port, sender, to_vip, **extra):
    message = {'type': 'punch', 'from': sender['virtual_ip'],
               'token': sender['relay_token'], 'to': to_vip}
    message.update(extra)
    return await send_first(server_port, message)


async def close_writers(*writers):
    for writer in writers:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def punch_setup(count=2, channels=0, extra=None):
    """An in-process server, `count` joined (unreachable) peers and a punching
    relay channel for the first `channels` of them (registered with `extra`
    added to the registration)."""
    server, srv, port = await start_intro()
    peers = [await raw_join(port, IP, dead_port()) for _ in range(count)]
    opened = [await PunchChannel(port, peer, extra=extra).open()
              for peer in peers[:channels]]
    return server, srv, port, peers, opened


async def teardown(srv, *channels):
    for channel in channels:
        await channel.close()
    await close_srv(srv)


@pytest.mark.asyncio
async def test_join_reply_says_the_server_coordinates_punches():
    server, srv, port, (a,), _ = await punch_setup(1)
    try:
        assert a['punch_supported'] is True
    finally:
        await close_srv(srv)


@pytest.mark.asyncio
async def test_only_a_channel_that_asked_for_punching_gets_punches():
    server, srv, port, (a, b, c, d), (chan_a,) = await punch_setup(4, 1)
    chan_b = await PunchChannel(port, b).open()
    no = await PunchChannel(port, c, punch_flag=False).open()
    maybe = await PunchChannel(port, d, punch_flag="yes").open()   # not True
    try:
        assert len(server.punch_channels) == 2
        for target in (c, d):
            reader, writer = await start_punch(port, a, target['virtual_ip'])
            failed = await read_json_frame(reader)
            assert failed['type'] == 'punch_failed'
            assert 'does not do hole punching' in failed['error']
            await close_writers(writer)
        assert no.messages == [] and maybe.messages == []
        # The flag goes away with the channel, and so does the punching.
        await chan_b.close()
        await wait_until(lambda: len(server.punch_channels) == 1)
        reader, writer = await start_punch(port, a, b['virtual_ip'])
        assert 'has no relay channel' in (await read_json_frame(reader))['error']
        await close_writers(writer)
    finally:
        await teardown(srv, chan_a, no, maybe)


@pytest.mark.asyncio
async def test_a_punch_gives_each_side_the_address_the_server_saw():
    """Each peer is sent the address its peer's relay channel connection comes
    from, as the server sees it: nothing the peers claim."""
    server, srv, port, (a, b), (chan_a, chan_b) = await punch_setup(2, 2)
    try:
        reader, writer = await start_punch(port, a, b['virtual_ip'])
        go = await read_json_frame(reader)
        target_go = await chan_b.next_go()
        assert go == {'type': 'punch_go', 'id': target_go['id'],
                      'peer': chan_b.endpoint}
        assert target_go == {'type': 'punch_go', 'id': go['id'],
                             'from': a['virtual_ip'], 'peer': chan_a.endpoint}
        assert chan_a.messages == []          # the initiator hears on its own connection
        # The slot is held until the initiator is done, then freed.
        assert len(server.pending_punches) == 1
        await close_writers(writer)
        await wait_until(lambda: not server.pending_punches)
    finally:
        await teardown(srv, chan_a, chan_b)


@pytest.mark.asyncio
async def test_a_peer_the_server_could_dial_back_is_reached_at_the_address_that_worked():
    server, srv, port, (b,), (chan_b,) = await punch_setup(1, 1)
    live = await asyncio.start_server(lambda r, w: None, IP, 0)
    live_port = live.sockets[0].getsockname()[1]
    try:
        a = await raw_join(port, IP, live_port)
        assert a['directly_reachable'] is True and a['virtual_ip'] not in server.relay_channels
        reader, writer = await start_punch(port, a, b['virtual_ip'])
        go = await read_json_frame(reader)
        assert go['peer'] == chan_b.endpoint
        assert (await chan_b.next_go())['peer'] == {'ip': IP, 'port': live_port}
        await close_writers(writer)
    finally:
        live.close()
        await live.wait_closed()
        await teardown(srv, chan_b)


@pytest.mark.asyncio
async def test_a_peer_that_cannot_be_reached_at_a_known_address_cannot_punch():
    """The initiator is neither dialable nor has a punching channel: the
    server has no address to give the target."""
    server, srv, port, (a, b, c), _ = await punch_setup(3, 0)
    chan_b = await PunchChannel(port, b).open()
    plain = await PunchChannel(port, c, punch_flag=False).open()
    try:
        for sender in (a, c):      # no channel at all / a channel that does not punch
            reader, writer = await start_punch(port, sender, b['virtual_ip'])
            failed = await read_json_frame(reader)
            assert failed['type'] == 'punch_failed'
            assert f"no address is known for {sender['virtual_ip']}" in failed['error']
            await close_writers(writer)
        assert chan_b.messages == [] and server.pending_punches == {}
    finally:
        await teardown(srv, chan_b, plain)


@pytest.mark.asyncio
async def test_claimed_addresses_are_never_handed_out():
    """A lying peer cannot name where its peer connects: addresses it puts in
    its punch request or its channel registration (as an address, in STUN's
    form or anywhere) are ignored, so it cannot aim a peer at a third host."""
    victim = {'ip': "203.0.113.200", 'port': 22}
    lies = dict(address=victim, peer=victim, ip=victim['ip'], port=22,
                mapped=victim, stun_address=victim, observed_address=victim,
                endpoint=[victim['ip'], 22], public_ip=victim['ip'])
    server, srv, port, (a, b), (chan_a, chan_b) = await punch_setup(2, 2, extra=lies)
    try:
        reader, writer = await start_punch(port, a, b['virtual_ip'], **lies)
        go = await read_json_frame(reader)
        target_go = await chan_b.next_go()
        assert go['peer'] == chan_b.endpoint and target_go['peer'] == chan_a.endpoint
        for message in (go, target_go):
            assert victim['ip'] not in json.dumps(message)
        await close_writers(writer)
    finally:
        await teardown(srv, chan_a, chan_b)


@pytest.mark.asyncio
async def test_punching_is_only_between_peers_that_joined():
    server, srv, port, (a, b, c), (chan_a, chan_b) = await punch_setup(3, 2)
    try:
        cases = [
            dict(sender=a, token="wrong"),
            dict(sender=a, token=b['relay_token']),                     # someone else's
            dict(sender={'virtual_ip': "10.0.0.99", 'relay_token': "x"}),  # never joined
            dict(sender=a, to="10.0.0.99"),                             # target never joined
            dict(sender=a, to=7),
            dict(sender=a, to=None),
            dict(sender=a, token=None),
        ]
        for case in cases:
            sender = case['sender']
            message = {'type': 'punch', 'from': sender['virtual_ip'],
                       'token': case.get('token', sender['relay_token']),
                       'to': case.get('to', b['virtual_ip'])}
            reader, writer = await send_first(port, message)
            failed = await read_json_frame(reader)
            assert failed['type'] == 'punch_failed', case
            assert 'only between peers that joined' in failed['error'], case
            await close_writers(writer)
        assert chan_b.messages == [] and server.pending_punches == {}

        # A target that joined but has no channel is refused too.
        reader, writer = await start_punch(port, a, c['virtual_ip'])
        assert 'has no relay channel' in (await read_json_frame(reader))['error']
        await close_writers(writer)
    finally:
        await teardown(srv, chan_a, chan_b)


@pytest.mark.asyncio
async def test_a_punch_that_is_never_closed_ends_at_the_session_timeout(monkeypatch):
    """The initiator keeps its connection open after the go and never closes
    it: the server hangs up on it and frees the slot."""
    monkeypatch.setattr(introduction_server, "PUNCH_SESSION_TIMEOUT", 0.3)
    server, srv, port, (a, b), (chan_a, chan_b) = await punch_setup(2, 2)
    try:
        reader, writer = await start_punch(port, a, b['virtual_ip'])
        await read_json_frame(reader)
        assert len(server.pending_punches) == 1
        assert await asyncio.wait_for(reader.read(), 3) == b""
        assert server.pending_punches == {}
        await close_writers(writer)
    finally:
        await teardown(srv, chan_a, chan_b)


@pytest.mark.asyncio
async def test_punch_rate_limit_per_sender(monkeypatch):
    monkeypatch.setattr(introduction_server, "PUNCH_RATE_LIMIT", 3)
    monkeypatch.setattr(introduction_server, "PUNCH_RATE_WINDOW", 60.0)
    server, srv, port, (a, b, c), _ = await punch_setup(3)
    try:
        async def punch_error(sender):
            reader, writer = await start_punch(port, sender, b['virtual_ip'])
            error = (await read_json_frame(reader))['error']
            await close_writers(writer)
            return error

        for _ in range(3):   # refused ones count (b has no channel)
            assert 'has no relay channel' in await punch_error(a)
        assert 'rate limit' in await punch_error(a)
        # Another sender has its own budget; so does a sender that is refused
        # for a bad token (it must not eat a's).
        assert 'has no relay channel' in await punch_error(c)
        reader, writer = await send_first(port, {
            'type': 'punch', 'from': a['virtual_ip'], 'token': "wrong",
            'to': b['virtual_ip']})
        assert 'only between peers that joined' in (await read_json_frame(reader))['error']
        await close_writers(writer)

        # Releasing the address forgets its count.
        server.release_virtual_ip(a['virtual_ip'])
        assert a['virtual_ip'] not in server._punch_times
        a2 = await raw_join(port, IP, dead_port())
        assert a2['virtual_ip'] == a['virtual_ip']
        assert 'has no relay channel' in await punch_error(a2)
    finally:
        await close_srv(srv)


@pytest.mark.asyncio
async def test_punch_rate_window_slides(monkeypatch):
    monkeypatch.setattr(introduction_server, "PUNCH_RATE_LIMIT", 1)
    monkeypatch.setattr(introduction_server, "PUNCH_RATE_WINDOW", 0.3)
    server, srv, port, (a, b), _ = await punch_setup()
    try:
        async def punch_error():
            reader, writer = await start_punch(port, a, b['virtual_ip'])
            error = (await read_json_frame(reader))['error']
            await close_writers(writer)
            return error

        assert 'has no relay channel' in await punch_error()
        assert 'rate limit' in await punch_error()
        await asyncio.sleep(0.4)
        assert 'has no relay channel' in await punch_error()
    finally:
        await close_srv(srv)


@pytest.mark.asyncio
@pytest.mark.parametrize("limit, first, second", [
    ("MAX_PENDING_PUNCHES_PER_SENDER", (0, 2), (0, 3)),
    ("MAX_PENDING_PUNCHES_PER_PEER", (0, 2), (1, 2)),
    ("MAX_PENDING_PUNCHES", (0, 2), (1, 3)),
])
async def test_punches_in_progress_are_capped(monkeypatch, limit, first, second):
    """Punches whose initiator has not finished are capped per sender, per
    target and in total; the next one is refused at once, and a slot is free
    again when the initiator closes its connection."""
    monkeypatch.setattr(introduction_server, limit, 1)
    server, srv, port, peers, channels = await punch_setup(4, 4)
    try:
        sender, target = peers[first[0]], peers[first[1]]
        first_reader, first_writer = await start_punch(
            port, sender, target['virtual_ip'])
        assert (await read_json_frame(first_reader))['type'] == 'punch_go'
        sender, target = peers[second[0]], peers[second[1]]
        told = channels[second[1]].gos.qsize()
        reader, writer = await start_punch(port, sender, target['virtual_ip'])
        failed = await read_json_frame(reader)
        assert failed['type'] == 'punch_failed' and 'too many' in failed['error']
        await close_writers(writer)
        assert channels[second[1]].gos.qsize() == told   # the target heard nothing

        await close_writers(first_writer)
        await wait_until(lambda: not server.pending_punches)
        reader, writer = await start_punch(port, sender, target['virtual_ip'])
        assert (await read_json_frame(reader))['type'] == 'punch_go'
        await close_writers(writer)
    finally:
        await teardown(srv, *channels)


@pytest.mark.asyncio
async def test_a_stalled_target_write_fails_the_punch_and_frees_its_slot(monkeypatch):
    """The target's channel stops draining: the punch_go write is cut off
    after RELAY_WRITE_TIMEOUT and the punch fails instead of hanging."""
    monkeypatch.setattr(introduction_server, "RELAY_WRITE_TIMEOUT", 0.2)
    monkeypatch.setattr(introduction_server, "MAX_PENDING_PUNCHES_PER_SENDER", 1)
    real_write_frame = introduction_server.write_frame

    async def never_drains(writer, data):
        if b'punch_go' in data and b'"from"' in data:   # the one for the target
            await asyncio.Event().wait()
        await real_write_frame(writer, data)

    monkeypatch.setattr(introduction_server, "write_frame", never_drains)
    server, srv, port, (a, b), (chan_a, chan_b) = await punch_setup(2, 2)
    opened = [chan_a, chan_b]
    try:
        for _ in range(2):   # the second would be 'too many' if the slot leaked
            reader, writer = await start_punch(port, a, b['virtual_ip'])
            failed = await asyncio.wait_for(read_json_frame(reader), 3)
            assert failed['type'] == 'punch_failed' and 'not reading' in failed['error']
            assert server.pending_punches == {}
            await close_writers(writer)
            # The server dropped b's channel; b registers a new one.
            await wait_until(lambda: b['virtual_ip'] not in server.relay_channels)
            opened.append(await PunchChannel(port, b).open())
    finally:
        await teardown(srv, *opened)


# --- PunchedChannel ---


class ChannelPair:
    """Two PunchedChannels joined by a loopback TCP connection; `closed`
    collects the channels as they close."""

    def __init__(self, handler_a=None, handler_b=None):
        self.handler_a, self.handler_b = handler_a or echo, handler_b or echo
        self.closed = []

    async def __aenter__(self):
        accepted = asyncio.get_running_loop().create_future()
        self.srv = await asyncio.start_server(
            lambda r, w: accepted.set_result((r, w)), IP, 0)
        port = self.srv.sockets[0].getsockname()[1]
        cr, cw = await asyncio.open_connection(IP, port)
        sr, sw = await accepted
        self.a = PunchedChannel("10.0.0.1", cr, cw, self.handler_a,
                                self.closed.append)
        self.b = PunchedChannel("10.0.0.2", sr, sw, self.handler_b,
                                self.closed.append)
        return self

    async def __aexit__(self, *exc):
        self.a.close()
        self.b.close()
        await self.a.wait_closed()
        await self.b.wait_closed()
        self.srv.close()
        await self.srv.wait_closed()


async def echo(payload):
    return b"re:" + payload


async def raw_channel_peer(handler=echo):
    """A PunchedChannel on one end of a TCP connection and the raw streams of
    the other end, for sending frames a real channel would not."""
    accepted = asyncio.get_running_loop().create_future()
    srv = await asyncio.start_server(
        lambda r, w: accepted.set_result((r, w)), IP, 0)
    reader, writer = await asyncio.open_connection(
        IP, srv.sockets[0].getsockname()[1])
    sr, sw = await accepted
    closed = []
    channel = PunchedChannel("10.0.0.9", sr, sw, handler, closed.append)
    return channel, reader, writer, closed, srv


def channel_frame(kind, request_id, payload=b""):
    body = bytes([kind]) + request_id.to_bytes(4, "big") + payload
    return len(body).to_bytes(4, "big") + body


@pytest.mark.asyncio
async def test_channel_matches_replies_to_requests_out_of_order():
    async def slow_or_fast(payload):
        await asyncio.sleep(0.3 if payload == b"slow" else 0)
        return b"re:" + payload

    order = []

    async def ask(channel, payload):
        reply = await channel.request(payload)
        order.append(payload)
        return reply

    async with ChannelPair(handler_b=slow_or_fast) as pair:
        slow, fast, other = await asyncio.gather(
            ask(pair.a, b"slow"), ask(pair.a, b"fast"), ask(pair.a, b"x"))
        assert (slow, fast, other) == (b"re:slow", b"re:fast", b"re:x")
        assert order[-1] == b"slow"


@pytest.mark.asyncio
async def test_channel_carries_requests_both_ways_on_one_connection():
    async with ChannelPair(lambda p: echo(b"a" + p), lambda p: echo(b"b" + p)) as pair:
        assert await pair.a.request(b"1") == b"re:b1"
        assert await pair.b.request(b"2") == b"re:a2"
        assert await asyncio.gather(*(pair.a.request(bytes([i])) for i in range(5))) \
            == [b"re:b" + bytes([i]) for i in range(5)]


@pytest.mark.asyncio
async def test_channel_reports_no_reply_without_closing():
    """A handler with nothing to say (None), one that raises, and one whose
    reply is over the cap all give the requester None at once; the channel is
    still usable."""
    async def handler(payload):
        if payload == b"none":
            return None
        if payload == b"boom":
            raise RuntimeError("handler failed")
        if payload == b"huge":
            return b"x" * (kademlia_dht.MAX_MESSAGE_SIZE + 1)
        return b"ok"

    async with ChannelPair(handler_b=handler) as pair:
        for payload in (b"none", b"boom", b"huge"):
            assert await asyncio.wait_for(pair.a.request(payload), 2) is None
        assert await pair.a.request(b"fine") == b"ok"
        assert pair.closed == []


@pytest.mark.asyncio
async def test_channel_limits_requests_in_flight_each_way(monkeypatch):
    monkeypatch.setattr(punch, "PUNCH_MAX_INFLIGHT", 2)
    release = asyncio.Event()

    async def held(payload):
        await release.wait()
        return b"done"

    # Outgoing: the third request is refused before it is sent.
    async with ChannelPair(handler_b=held) as pair:
        first = asyncio.create_task(pair.a.request(b"1"))
        second = asyncio.create_task(pair.a.request(b"2"))
        await wait_until(lambda: len(pair.a._pending) == 2)
        with pytest.raises(ConnectionError, match="too many requests"):
            await pair.a.request(b"3")
        release.set()
        assert await first == await second == b"done"

    # Incoming: a peer that sends more than that gets "no reply" for the extra.
    release.clear()
    channel, reader, writer, closed, srv = await raw_channel_peer(held)
    try:
        for request_id in (1, 2, 3):
            writer.write(channel_frame(punch.REQUEST, request_id, b"q"))
        await writer.drain()
        frame = await read_frame(reader)
        assert frame == bytes([punch.NO_REPLY]) + (3).to_bytes(4, "big")
        release.set()
        replies = {await read_frame(reader), await read_frame(reader)}
        assert replies == {bytes([punch.REPLY]) + i.to_bytes(4, "big") + b"done"
                           for i in (1, 2)}
    finally:
        channel.close()
        await channel.wait_closed()
        writer.close()
        srv.close()
        await srv.wait_closed()


@pytest.mark.asyncio
@pytest.mark.parametrize("raw", [
    channel_frame(9, 1, b"?"),                                   # unknown kind
    len(b"abc").to_bytes(4, "big") + b"abc",                     # shorter than a header
    (punch.MAX_PUNCH_FRAME_SIZE + 1).to_bytes(4, "big"),         # over the size cap
])
async def test_channel_is_closed_by_a_frame_it_cannot_accept(raw):
    channel, reader, writer, closed, srv = await raw_channel_peer()
    try:
        writer.write(raw)
        await writer.drain()
        assert await asyncio.wait_for(reader.read(), 3) == b""   # hung up on us
        assert closed == [channel] and channel.closed
    finally:
        await channel.wait_closed()
        writer.close()
        srv.close()
        await srv.wait_closed()


@pytest.mark.asyncio
async def test_channel_closes_after_the_idle_timeout(monkeypatch):
    monkeypatch.setattr(punch, "PUNCH_IDLE_TIMEOUT", 0.3)
    async with ChannelPair() as pair:
        assert await pair.a.request(b"x") == b"re:x"
        await wait_until(lambda: pair.a.closed and pair.b.closed)
        assert set(pair.closed) == {pair.a, pair.b}
        with pytest.raises(ConnectionError, match="closed"):
            await pair.a.request(b"x")


@pytest.mark.asyncio
async def test_channel_request_times_out_but_the_channel_stays_open(monkeypatch):
    monkeypatch.setattr(punch, "PUNCH_REQUEST_TIMEOUT", 0.3)
    never = asyncio.Event()

    async def hang(payload):
        await never.wait()

    async with ChannelPair(handler_b=hang) as pair:
        with pytest.raises(ConnectionError, match="no reply within"):
            await pair.a.request(b"x")
        assert pair.a._pending == {} and not pair.a.closed


@pytest.mark.asyncio
async def test_closing_a_channel_fails_its_requests_and_cancels_its_handlers():
    started, cancelled = asyncio.Event(), []

    async def hang(payload):
        started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancelled.append(1)
            raise

    async with ChannelPair(handler_b=hang) as pair:
        waiting = asyncio.create_task(pair.a.request(b"x"))
        await asyncio.wait_for(started.wait(), 2)
        pair.a.close()   # the peer hangs up on b's handler, and on a's request
        with pytest.raises(ConnectionError, match="closed"):
            await waiting
        await wait_until(lambda: pair.b.closed and cancelled)
        assert pair.a._handlers == set() == pair.b._handlers
        pair.a.close()   # twice is harmless
        assert pair.closed.count(pair.a) == 1


@pytest.mark.asyncio
async def test_a_peer_that_vanishes_mid_request_fails_it_at_once():
    channel, reader, writer, closed, srv = await raw_channel_peer()
    try:
        waiting = asyncio.create_task(channel.request(b"x"))
        assert (await read_frame(reader))[0] == punch.REQUEST
        writer.close()
        with pytest.raises(ConnectionError, match="closed"):
            await asyncio.wait_for(waiting, 2)
    finally:
        await channel.wait_closed()
        srv.close()
        await srv.wait_closed()


@pytest.mark.asyncio
async def test_a_channel_whose_peer_stops_reading_is_dropped(monkeypatch):
    monkeypatch.setattr(punch, "PUNCH_WRITE_TIMEOUT", 0.2)

    async def never_drains(writer, data):
        await asyncio.Event().wait()

    monkeypatch.setattr(punch, "write_frame", never_drains)
    async with ChannelPair() as pair:
        with pytest.raises(ConnectionError, match="not reading"):
            await pair.a.request(b"x")
        await wait_until(lambda: pair.a.closed)


# --- Hellos on the listening port ---


@pytest.fixture
def hello_node(tmp_path):
    """A listening KademliaNode whose inbound PUNCH hellos go to a PunchClient."""
    async def make(punch_ip="127.0.0.1", punch_id="the-id", accept=True):
        client = PunchClient((IP, 1), "10.0.0.1", "tok", (IP, 0), echo)
        node = KademliaNode(1, IP, 0, key_path=str(tmp_path / "hello.key"))
        if accept:
            node.punch_accept = client.accept
        future = asyncio.get_running_loop().create_future()
        client._expected[punch_id] = (punch_ip, future)
        srv = await asyncio.start_server(node.handle_connection, IP, 0)
        return client, future, srv, srv.sockets[0].getsockname()[1]
    return make


async def hello(port, punch_id):
    reader, writer = await asyncio.open_connection(IP, port)
    await write_frame(writer, PUNCH_HELLO + punch_id)
    return reader, writer


@pytest.mark.asyncio
async def test_a_hello_from_the_named_peer_with_the_right_id_is_accepted(hello_node):
    client, future, srv, port = await hello_node()
    try:
        reader, writer = await hello(port, b"the-id")
        assert await asyncio.wait_for(read_frame(reader), 2) == PUNCH_HELLO + b"the-id"
        accepted_reader, accepted_writer = await asyncio.wait_for(future, 2)
        # The connection is kept open and usable.
        accepted_writer.write(b"x")
        assert await asyncio.wait_for(reader.read(1), 2) == b"x"
        await close_writers(writer, accepted_writer)
    finally:
        srv.close()
        await srv.wait_closed()


@pytest.mark.asyncio
@pytest.mark.parametrize("sent_id, expected_ip", [
    (b"some-other-id", "127.0.0.1"),     # not a punch in progress
    (b"the-id", "127.0.0.2"),            # right id, but the server named another IP
    (b"", "127.0.0.1"),
    (b"\xff\xfe", "127.0.0.1"),          # not even text
    (b"x" * 5000, "127.0.0.1"),
])
async def test_a_hello_that_is_not_the_expected_peer_is_dropped(
        hello_node, sent_id, expected_ip):
    client, future, srv, port = await hello_node(punch_ip=expected_ip)
    try:
        reader, writer = await hello(port, sent_id)
        assert await asyncio.wait_for(reader.read(), 2) == b""   # no echo, hung up
        assert not future.done()
        writer.close()
    finally:
        srv.close()
        await srv.wait_closed()


@pytest.mark.asyncio
async def test_a_punch_can_be_answered_only_once(hello_node):
    client, future, srv, port = await hello_node()
    try:
        first_reader, first_writer = await hello(port, b"the-id")
        await asyncio.wait_for(read_frame(first_reader), 2)
        second_reader, second_writer = await hello(port, b"the-id")
        assert await asyncio.wait_for(second_reader.read(), 2) == b""
        await close_writers(first_writer, second_writer, (await future)[1])
    finally:
        srv.close()
        await srv.wait_closed()


@pytest.mark.asyncio
async def test_a_node_without_hole_punching_treats_a_hello_as_an_unknown_command(
        hello_node):
    client, future, srv, port = await hello_node(accept=False)
    try:
        reader, writer = await hello(port, b"the-id")
        assert await asyncio.wait_for(reader.read(), 2) == b""
        assert not future.done()
        writer.close()
    finally:
        srv.close()
        await srv.wait_closed()


# --- _exchange: direct, then punched, then relayed ---


class Hooks:
    """Recording stand-ins for the punch and relay hooks, and for direct dials."""

    def __init__(self, monkeypatch, punch_reply=None, relay_reply=None,
                 direct_ok=False, punch_error=None):
        self.calls = []
        self.punch_reply, self.relay_reply = punch_reply, relay_reply
        self.punch_error = punch_error
        self.direct_ok = direct_ok
        real_connect = kademlia_dht.connect

        async def connect(ip, port):
            self.calls.append('direct')
            if not self.direct_ok:
                raise ConnectionRefusedError("nobody home")
            return await real_connect(ip, port)

        monkeypatch.setattr(kademlia_dht, "connect", connect)

    async def punch(self, node, request):
        self.calls.append('punch')
        if self.punch_error is not None:
            raise self.punch_error
        return self.punch_reply

    async def relay(self, node, request):
        self.calls.append('relay')
        return self.relay_reply


async def exchange_node(tmp_path, hooks, with_punch=True, with_relay=True):
    node = KademliaNode(1, IP, 0, key_path=str(tmp_path / "ex.key"))
    node.punch = hooks.punch if with_punch else None
    node.relay = hooks.relay if with_relay else None
    return node


@pytest.mark.asyncio
async def test_exchange_dials_first_and_uses_no_indirect_path_when_it_works(
        tmp_path, monkeypatch):
    peer = KademliaNode(2, IP, 0, key_path=str(tmp_path / "peer.key"))
    srv = await asyncio.start_server(peer.handle_connection, IP, 0)
    hooks = Hooks(monkeypatch, direct_ok=True)
    node = await exchange_node(tmp_path, hooks)
    try:
        contact = Node(2, IP, srv.sockets[0].getsockname()[1], virtual_ip="10.0.0.2")
        for reachable in (None, True):
            contact.reachable = reachable
            assert await node._exchange(contact, b"PING") == b"PONG"
        assert hooks.calls == ['direct', 'direct']
    finally:
        srv.close()
        await srv.wait_closed()


@pytest.mark.asyncio
@pytest.mark.parametrize("punch_reply, relay_reply, calls, expected", [
    (b"punched", b"relayed", ['direct', 'punch'], b"punched"),
    (None, b"relayed", ['direct', 'punch', 'relay'], b"relayed"),
    (None, None, ['direct', 'punch', 'relay'], None),
])
async def test_exchange_tries_the_punched_path_between_direct_and_relay(
        tmp_path, monkeypatch, punch_reply, relay_reply, calls, expected):
    hooks = Hooks(monkeypatch, punch_reply, relay_reply)
    node = await exchange_node(tmp_path, hooks)
    contact = Node(2, IP, 1, reachable=None, virtual_ip="10.0.0.2")
    assert await node._exchange(contact, b"PING") == expected
    assert hooks.calls == calls


@pytest.mark.asyncio
@pytest.mark.parametrize("punch_reply, relay_reply, direct_ok, calls, expected", [
    (b"punched", b"relayed", True, ['punch'], b"punched"),
    (None, b"relayed", True, ['punch', 'relay'], b"relayed"),
    (None, None, True, ['punch', 'relay', 'direct'], b"PONG"),   # direct is the last resort
    (None, None, False, ['punch', 'relay', 'direct'], None),
])
async def test_exchange_skips_the_dial_for_a_contact_known_to_be_unreachable(
        tmp_path, monkeypatch, punch_reply, relay_reply, direct_ok, calls,
        expected):
    peer = KademliaNode(2, IP, 0, key_path=str(tmp_path / "peer.key"))
    srv = await asyncio.start_server(peer.handle_connection, IP, 0)
    hooks = Hooks(monkeypatch, punch_reply, relay_reply, direct_ok=direct_ok)
    node = await exchange_node(tmp_path, hooks)
    try:
        contact = Node(2, IP, srv.sockets[0].getsockname()[1], reachable=False,
                       virtual_ip="10.0.0.2")
        assert await node._exchange(contact, b"PING") == expected
        assert hooks.calls == calls
    finally:
        srv.close()
        await srv.wait_closed()


@pytest.mark.asyncio
async def test_exchange_without_punching_behaves_as_before(tmp_path, monkeypatch):
    hooks = Hooks(monkeypatch, relay_reply=b"relayed")
    node = await exchange_node(tmp_path, hooks, with_punch=False)
    assert await node._exchange(Node(2, IP, 1, virtual_ip="10.0.0.2"), b"PING") == b"relayed"
    assert hooks.calls == ['direct', 'relay']
    hooks.calls.clear()
    assert await node._exchange(
        Node(2, IP, 1, reachable=False, virtual_ip="10.0.0.2"), b"PING") == b"relayed"
    assert hooks.calls == ['relay']
    hooks.calls.clear()
    node = await exchange_node(tmp_path, hooks, with_punch=False, with_relay=False)
    assert await node._exchange(Node(2, IP, 1, virtual_ip="10.0.0.2"), b"PING") is None
    assert hooks.calls == ['direct']


@pytest.mark.asyncio
async def test_exchange_needs_a_virtual_ip_for_the_indirect_paths(tmp_path, monkeypatch):
    hooks = Hooks(monkeypatch, b"punched", b"relayed")
    node = await exchange_node(tmp_path, hooks)
    for reachable in (None, False):
        assert await node._exchange(Node(2, IP, 1, reachable=reachable), b"PING") is None
    assert hooks.calls == ['direct', 'direct']


@pytest.mark.asyncio
async def test_a_punch_hook_that_raises_falls_back_to_the_relay(tmp_path, monkeypatch, capsys):
    hooks = Hooks(monkeypatch, relay_reply=b"relayed",
                  punch_error=RuntimeError("boom"))
    node = await exchange_node(tmp_path, hooks)
    contact = Node(2, IP, 1, reachable=False, virtual_ip="10.0.0.2")
    assert await node._exchange(contact, b"PING") == b"relayed"
    assert hooks.calls == ['punch', 'relay']
    assert "boom" in capsys.readouterr().out


# --- Nodes behind simulated NATs ---


class Lab:
    """An in-process introduction server and P2PNodes joined to it. A node
    "behind a NAT" has its port held by a Firewall (see the top of the file):
    nobody can dial it, and the server's dial-back fails. Records every relay
    request and every punch the server coordinates."""

    def __init__(self, tmp_path, monkeypatch):
        self.tmp_path, self.monkeypatch = tmp_path, monkeypatch
        self.nodes, self.firewalls = [], []
        self.hidden = set()    # ports of nodes with a listener the "NAT" hides
        self.relay_calls, self.punches = [], []

    async def __aenter__(self):
        self.server, self.srv, self.port = await start_intro()
        real_handle_punch = self.server._handle_punch

        async def spy(*args):
            self.punches.append(args[2])
            await real_handle_punch(*args)

        self.server._handle_punch = spy
        real_check = self.server.check_directly_reachable

        async def check(ip, port, observed_ip):
            return False if port in self.hidden else await real_check(
                ip, port, observed_ip)

        self.server.check_directly_reachable = check
        real_request = RelayClient.request

        async def counting(client, to_vip, payload):
            self.relay_calls.append(to_vip)
            return await real_request(client, to_vip, payload)

        self.monkeypatch.setattr(RelayClient, "request", counting)
        real_connect = kademlia_dht.connect

        async def connect(ip, port):
            if port in self.hidden:
                raise ConnectionRefusedError("hidden by the NAT")
            return await real_connect(ip, port)

        self.monkeypatch.setattr(kademlia_dht, "connect", connect)
        return self

    async def __aexit__(self, *exc):
        for node in self.nodes:
            await node.stop()
        for firewall in self.firewalls:
            firewall.close()
        await close_srv(self.srv)

    async def node(self, name, behind_nat=True, listener=False, **kwargs):
        """Join a node. `listener`: behind a NAT but listening (direct dials
        and the dial-back are refused by the stand-in NAT, not by a dead port);
        otherwise behind_nat nodes sit behind a Firewall and a plain node
        listens and is reachable."""
        kwargs.setdefault('hole_punching', True)
        key = str(self.tmp_path / f"{name}.key")
        if behind_nat and not listener:
            firewall = Firewall()
            self.firewalls.append(firewall)
            await asyncio.sleep(0.05)   # let its accept queue fill
            node = P2PNode(IP, firewall.port, key_path=key, **kwargs)
        else:
            node = P2PNode(IP, dead_port(), key_path=key, **kwargs)
            if listener:
                self.hidden.add(node.port)
            await node.start()
        self.nodes.append(node)
        await node.join_network((IP, self.port))
        assert node.directly_reachable is (not behind_nat)
        return node

    @staticmethod
    def contact(node, reachable=False):
        return Node(node.id, IP, node.port, reachable=reachable,
                    virtual_ip=node.virtual_ip)


def both_ends(a, b):
    """The channels a and b hold to each other."""
    return a.punch.channels[b.virtual_ip], b.punch.channels[a.virtual_ip]


@pytest.mark.asyncio
async def test_the_stand_in_nat_really_blocks_dials():
    firewall = Firewall()
    await asyncio.sleep(0.05)
    try:
        with pytest.raises(OSError):
            await kademlia_dht.connect(IP, firewall.port)
    finally:
        firewall.close()


@pytest.mark.asyncio
async def test_two_nodes_behind_nats_open_a_direct_connection(tmp_path, monkeypatch):
    """The punched path, not the relay: b's bootstrap ping to a is carried by
    a TCP connection that both nodes opened from their own listening ports
    (a simultaneous open: each one's SYN is dropped until the other's
    connect() is under way), and DHT traffic then flows over it both ways."""
    async with Lab(tmp_path, monkeypatch) as lab:
        a = await lab.node("a")
        b = await lab.node("b")
        assert a.punch is not None and a.directly_reachable is False
        ca, cb = both_ends(a, b)
        assert ca.writer.get_extra_info('sockname')[1] == a.port
        assert ca.writer.get_extra_info('peername')[1] == b.port
        assert cb.writer.get_extra_info('sockname')[1] == b.port
        assert cb.writer.get_extra_info('peername')[1] == a.port
        assert list(a.punch.channels) == [b.virtual_ip]
        assert list(b.punch.channels) == [a.virtual_ip]

        assert await b.kademlia._exchange(lab.contact(a), b"PING") == b"PONG"
        assert await a.kademlia._exchange(lab.contact(b), b"PING") == b"PONG"
        assert both_ends(a, b) == (ca, cb)   # the same connection, reused
        assert lab.relay_calls == []
        assert lab.server.pending_relays == {} and lab.server._relay_times == {}
        assert len(lab.punches) == 1 and lab.server.pending_punches == {}


@pytest.mark.asyncio
async def test_dht_records_are_stored_and_found_over_the_punched_connection(
        tmp_path, monkeypatch):
    async with Lab(tmp_path, monkeypatch) as lab:
        a = await lab.node("a")
        b = await lab.node("b")
        assert await b.register_domain("punched.test", "10.9.9.9")
        key = kademlia_dht.sha1_hash("punched.test")
        assert a.kademlia.data[key][0] == b.kademlia.owner_public_key
        # a asks b, whose local copy answers: the signed record comes back
        # over the same connection and is verified like any other.
        a.kademlia.routing_table.add(lab.contact(b))
        a.kademlia.data.clear()
        record, _ = await a.kademlia.find_record(key)
        assert record.value == "10.9.9.9" and record.owner == b.kademlia.owner_public_key
        assert lab.relay_calls == []


@pytest.mark.asyncio
async def test_a_punched_connection_is_reused_and_concurrent_requests_share_one_punch(
        tmp_path, monkeypatch):
    async with Lab(tmp_path, monkeypatch) as lab:
        a = await lab.node("a")
        b = await lab.node("b")
        contact_a = lab.contact(a)
        first, _ = both_ends(b, a)
        for _ in range(5):
            assert await b.kademlia._exchange(contact_a, b"PING") == b"PONG"
        assert both_ends(b, a)[0] is first and len(lab.punches) == 1

        # No channel: five requests at once are one punch.
        first.close()
        await wait_until(lambda: not a.punch.channels and not b.punch.channels)
        b.punch._retry_after.clear()
        replies = await asyncio.gather(
            *(b.kademlia._exchange(contact_a, b"PING") for _ in range(5)))
        assert replies == [b"PONG"] * 5
        assert len(lab.punches) == 2 and lab.relay_calls == []
        assert both_ends(b, a)[0] is not first


@pytest.mark.asyncio
async def test_an_idle_channel_is_closed_and_activity_keeps_it_open(
        tmp_path, monkeypatch):
    monkeypatch.setattr(punch, "PUNCH_IDLE_TIMEOUT", 0.6)
    async with Lab(tmp_path, monkeypatch) as lab:
        a = await lab.node("a")
        b = await lab.node("b")
        channel = both_ends(b, a)[0]
        for _ in range(6):   # 1.2 s of traffic, twice the idle timeout
            await asyncio.sleep(0.2)
            assert await b.kademlia._exchange(lab.contact(a), b"PING") == b"PONG"
        assert both_ends(b, a)[0] is channel and len(lab.punches) == 1

        await wait_until(lambda: not a.punch.channels and not b.punch.channels,
                         tries=200)
        assert await b.kademlia._exchange(lab.contact(a), b"PING") == b"PONG"
        assert len(lab.punches) == 2 and lab.relay_calls == []


@pytest.mark.asyncio
async def test_both_nodes_punching_to_each_other_at_once_end_up_with_one_connection(
        tmp_path, monkeypatch):
    async with Lab(tmp_path, monkeypatch) as lab:
        a = await lab.node("a")
        b = await lab.node("b")
        both_ends(a, b)[0].close()
        await wait_until(lambda: not a.punch.channels and not b.punch.channels)
        for node in (a, b):
            node.punch._retry_after.clear()
        replies = await asyncio.gather(
            a.kademlia._exchange(lab.contact(b), b"PING"),
            b.kademlia._exchange(lab.contact(a), b"PING"))
        assert replies == [b"PONG", b"PONG"]
        ca, cb = both_ends(a, b)
        assert ca.writer.get_extra_info('sockname') == cb.writer.get_extra_info('peername')
        assert lab.relay_calls == [] and len(lab.punches) == 3


@pytest.mark.asyncio
async def test_punching_through_a_listener_that_gets_the_first_syn(tmp_path, monkeypatch):
    """Nodes that listen, with the "NAT" hiding them only from direct dials
    and the dial-back: whichever node connects first reaches the other's
    listener, which hands the connection to the punch (the accept path, as
    opposed to a simultaneous open)."""
    async with Lab(tmp_path, monkeypatch) as lab:
        a = await lab.node("a", listener=True)
        accepts = []
        real_accept = a.kademlia.punch_accept

        async def spy(reader, writer, hello):
            accepts.append(hello)
            await real_accept(reader, writer, hello)

        a.kademlia.punch_accept = spy
        b = await lab.node("b", listener=True)
        ca, cb = both_ends(a, b)
        assert await b.kademlia._exchange(lab.contact(a), b"PING") == b"PONG"
        assert await a.kademlia._exchange(lab.contact(b), b"PING") == b"PONG"
        assert lab.relay_calls == []
        assert ca.writer.get_extra_info('sockname') == cb.writer.get_extra_info('peername')
        # The listener took one side of it (or, rarely, the SYNs crossed).
        assert len(accepts) <= 1


@pytest.mark.asyncio
async def test_listening_nodes_share_their_port_only_when_asked_to(tmp_path):
    plain = P2PNode(IP, dead_port(), key_path=str(tmp_path / "p.key"))
    punching = P2PNode(IP, dead_port(), key_path=str(tmp_path / "q.key"),
                       hole_punching=True)
    mapping = P2PNode(IP, dead_port(), key_path=str(tmp_path / "r.key"),
                      stun=True)
    nodes = [plain, punching, mapping]
    try:
        for node in nodes:
            await node.start()
        reuse = [n.server.sockets[0].getsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT)
                 for n in nodes]
        assert reuse == [0, 1, 1]
    finally:
        for node in nodes:
            await node.stop()


# --- When the punch does not work, the relay does ---


@pytest.mark.asyncio
async def test_a_target_that_never_connects_falls_back_to_the_relay(tmp_path, monkeypatch):
    """a ignores the punch (its NAT drops b's SYNs and a sends none of its
    own): b gives up when the window ends and the relay carries the request."""
    monkeypatch.setattr(punch, "PUNCH_WINDOW", 0.8)
    monkeypatch.setattr(punch, "PUNCH_RETRY_DELAY", 1.2)
    async with Lab(tmp_path, monkeypatch) as lab:
        a = await lab.node("a")
        a.relay.punch_handler = lambda message: None   # a never joins a punch
        started = asyncio.get_running_loop().time()
        b = await lab.node("b")   # its bootstrap ping: punch fails, relay answers
        elapsed = asyncio.get_running_loop().time() - started
        assert 0.8 <= elapsed < 4    # the window, then the relay
        assert lab.relay_calls and len(lab.punches) == 1
        assert not a.punch.channels and not b.punch.channels
        assert lab.contact(a).virtual_ip in [c.virtual_ip for bucket in
                                             b.kademlia.routing_table.buckets
                                             for c in bucket.nodes]
        assert lab.server.pending_punches == {}

        # No second punch while the first failure is fresh; the relay serves.
        calls = len(lab.relay_calls)
        assert await b.kademlia._exchange(lab.contact(a), b"PING") == b"PONG"
        assert len(lab.punches) == 1 and len(lab.relay_calls) == calls + 1

        # After the delay it tries again.
        await asyncio.sleep(1.3)
        a.relay.punch_handler = a.punch.handle_go
        assert await b.kademlia._exchange(lab.contact(a), b"PING") == b"PONG"
        assert len(lab.punches) == 2 and a.punch.channels and b.punch.channels
        await wait_until(lambda: lab.server.pending_punches == {})
        assert a.punch._expected == {} and b.punch._expected == {}


@pytest.mark.asyncio
async def test_a_target_that_does_not_punch_is_relayed_at_once(tmp_path, monkeypatch):
    async with Lab(tmp_path, monkeypatch) as lab:
        a = await lab.node("a", hole_punching=False)
        assert a.punch is None and lab.server.punch_channels == set()
        started = asyncio.get_running_loop().time()
        b = await lab.node("b")
        assert asyncio.get_running_loop().time() - started < 1.5   # not the window
        assert len(lab.relay_calls) >= 1 and not b.punch.channels
        # The server refused (it never sent a punch_request to a).
        assert len(lab.punches) == 1 and lab.server.pending_punches == {}


@pytest.mark.asyncio
async def test_a_server_that_cannot_coordinate_punches_leaves_the_relay_alone(
        tmp_path, capsys):
    """An older introduction server: its join reply has no punch_supported.
    The node joins, uses the relay, and sets up nothing for punching."""
    async def old_server(reader, writer):
        await reader.read(4096)
        writer.write(json.dumps({'virtual_ip': "10.0.0.5", 'relay_token': "t",
                                 'directly_reachable': True,
                                 'nearby_peers': []}).encode())
        await writer.drain()
        writer.close()

    srv, port = await scripted_server(old_server)
    node = P2PNode(IP, dead_port(), key_path=str(tmp_path / "n.key"),
                   hole_punching=True)
    try:
        await node.join_network((IP, port))
        assert node.virtual_ip == "10.0.0.5" and node.relay is not None
        assert node.punch is None and node.kademlia.punch is None
        assert node.kademlia.punch_accept is None and node.relay.punch_handler is None
        assert "does not coordinate hole punching" in capsys.readouterr().out
    finally:
        await close_srv(srv)


@pytest.mark.asyncio
async def test_a_channel_that_stops_answering_falls_back_to_the_relay(
        tmp_path, monkeypatch):
    monkeypatch.setattr(punch, "PUNCH_REQUEST_TIMEOUT", 0.4)
    async with Lab(tmp_path, monkeypatch) as lab:
        a = await lab.node("a")
        b = await lab.node("b")
        _, on_a = both_ends(b, a)[0], both_ends(a, b)[0]

        async def hang(payload):
            await asyncio.Event().wait()

        on_a.handler = hang   # the connection is up but a stopped answering
        assert lab.relay_calls == []
        assert await b.kademlia._exchange(lab.contact(a), b"PING") == b"PONG"
        assert len(lab.relay_calls) == 1       # answered by the relay
        assert not b.punch.channels and a.virtual_ip in b.punch._retry_after
        # Not punched again right away.
        assert await b.kademlia._exchange(lab.contact(a), b"PING") == b"PONG"
        assert len(lab.punches) == 1


@pytest.mark.asyncio
async def test_punches_and_channels_are_capped(tmp_path, monkeypatch):
    monkeypatch.setattr(punch, "MAX_PUNCHED_CHANNELS", 1)
    async with Lab(tmp_path, monkeypatch) as lab:
        a = await lab.node("a")
        b = await lab.node("b")      # b -> a: one channel each
        c = await lab.node("c")      # c -> a and c -> b: a and b are full
        assert len(a.punch.channels) == len(b.punch.channels) == 1
        assert list(a.punch.channels) == [b.virtual_ip]   # not replaced by c
        assert all(len(n.punch.channels) <= 1 for n in (a, b, c))
        # The refused channels were closed, not left half-open, and c still
        # reaches both: the relay answers.
        assert await c.kademlia._exchange(lab.contact(a), b"PING") == b"PONG"
        assert await c.kademlia._exchange(lab.contact(b), b"PING") == b"PONG"
        assert lab.relay_calls


@pytest.mark.asyncio
async def test_only_a_few_punches_run_at_once(tmp_path, monkeypatch):
    monkeypatch.setattr(punch, "PUNCH_MAX_ATTEMPTS", 1)
    async with Lab(tmp_path, monkeypatch) as lab:
        a = await lab.node("a")
        b = await lab.node("b")
        c = await lab.node("c")
        for node in (a, b, c):
            for channel in list(node.punch.channels.values()):
                channel.close()
            node.punch._retry_after.clear()
        await wait_until(lambda: not any(n.punch.channels for n in (a, b, c)))
        before = len(lab.punches)
        replies = await asyncio.gather(
            c.kademlia._exchange(lab.contact(a), b"PING"),
            c.kademlia._exchange(lab.contact(b), b"PING"))
        assert replies == [b"PONG", b"PONG"]
        assert len(lab.punches) - before == 1       # the second went to the relay
        assert len(lab.relay_calls) == 1


@pytest.mark.asyncio
async def test_a_node_joins_only_a_few_punches_at_once(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(punch, "PUNCH_MAX_RESPONSES", 0)
    monkeypatch.setattr(punch, "PUNCH_WINDOW", 0.5)
    async with Lab(tmp_path, monkeypatch) as lab:
        a = await lab.node("a")
        await lab.node("b")
        assert "Ignoring a punch from" in capsys.readouterr().out
        assert a.punch._responders == set() and not a.punch.channels
        assert lab.relay_calls       # b's ping went by the relay instead


# --- STUN decides whether to punch ---


@pytest.mark.asyncio
async def test_an_endpoint_dependent_nat_skips_hole_punching(tmp_path, monkeypatch, capsys):
    async with Lab(tmp_path, monkeypatch) as lab, \
            FakeTcpServer(tcp_report_source, "127.0.0.1") as honest, \
            FakeTcpServer(tcp_shifted, "127.0.0.2") as shifted:
        a = await lab.node("a")
        b = await lab.node("b", stun=True,
                           stun_servers=[honest.address, shifted.address])
        assert b.nat_mapping == stun.ENDPOINT_DEPENDENT
        assert b.punch is None and b.kademlia.punch is None
        assert b.relay.punch_handler is None
        assert "Not hole punching" in capsys.readouterr().out
        # Straight to the relay: no punch was asked of the server for b's
        # ping, and b's channel is not registered as one that punches.
        assert lab.punches == [] and lab.relay_calls
        assert len(lab.server.punch_channels) == 1       # a's only

        # a cannot punch to b either: the server knows b does not.
        assert await a.kademlia._exchange(lab.contact(b), b"PING") == b"PONG"
        assert len(lab.punches) == 1 and not a.punch.channels


@pytest.mark.asyncio
async def test_an_endpoint_independent_nat_punches_and_stun_asked_from_the_listening_port(
        tmp_path, monkeypatch):
    async with Lab(tmp_path, monkeypatch) as lab, \
            FakeTcpServer(tcp_report_source, "127.0.0.1") as one, \
            FakeTcpServer(tcp_report_source, "127.0.0.2") as two:
        await lab.node("a")
        b = await lab.node("b", stun=True, stun_servers=[one.address, two.address])
        assert b.nat_mapping == stun.ENDPOINT_INDEPENDENT
        # Both servers saw the node's listening port, so that is where the
        # query came from; and that is the address the node reports.
        assert [peer[1] for _, peer in one.requests + two.requests] == [b.port] * 2
        assert b.stun_address == (IP, b.port)
        assert b.punch is not None and b.punch.channels and lab.relay_calls == []


@pytest.mark.asyncio
async def test_without_a_stun_answer_the_node_carries_on_and_still_punches(
        tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(stun, "STUN_TCP_TIMEOUT", 0.3)
    async with Lab(tmp_path, monkeypatch) as lab:
        await lab.node("a")
        b = await lab.node("b", stun=True,
                           stun_servers=[(IP, dead_port()), (IP, dead_port())])
        assert b.nat_mapping == stun.UNKNOWN and b.stun_address is None
        assert b.punch is not None and b.punch.channels and lab.relay_calls == []
        # A STUN failure that is an exception (here: the port is not shareable)
        # is reported and ignored too.
        async def broken(*args, **kwargs):
            raise OSError("no sockets today")

        monkeypatch.setattr(p2p_node_module, "detect_mapping", broken)
        c = await lab.node("c", stun=True)
        assert c.nat_mapping is None and "STUN mapping test failed" in capsys.readouterr().out
        assert c.punch is not None


@pytest.mark.asyncio
async def test_stun_is_not_asked_by_a_node_that_is_directly_reachable(tmp_path, monkeypatch):
    async with Lab(tmp_path, monkeypatch) as lab, \
            FakeTcpServer(tcp_report_source, "127.0.0.1") as one:
        a = await lab.node("a", behind_nat=False, stun=True,
                           stun_servers=[one.address, one.address])
        assert a.nat_mapping is None and one.connections == 0
        # And a node that does not ask for STUN never asks.
        b = await lab.node("b")
        assert b.nat_mapping is None and one.connections == 0


# --- What the peer accepts from the server ---


@pytest.fixture
def dials(monkeypatch):
    """Every peer address a PunchClient connects to (not the server)."""
    made = []
    real = punch.connect_from

    async def spy(local_addr, remote_addr, timeout):
        made.append(remote_addr)
        return await real(local_addr, remote_addr, timeout)

    monkeypatch.setattr(punch, "connect_from", spy)
    return made


def go_server(go_message):
    """A scripted introduction server that answers a punch with `go_message`."""
    async def script(reader, writer):
        await reader.read(4096)
        await write_frame(writer, json.dumps(go_message).encode())
        await asyncio.sleep(0.3)
        writer.close()
    return script


@pytest.mark.asyncio
@pytest.mark.parametrize("go", [
    {'type': 'punch_failed', 'error': "no"},
    {'type': 'punch_go', 'id': "x", 'peer': {'ip': "not-an-ip", 'port': 80}},
    {'type': 'punch_go', 'id': "x", 'peer': {'ip': 7, 'port': 80}},
    {'type': 'punch_go', 'id': "x", 'peer': {'ip': None, 'port': 80}},
    {'type': 'punch_go', 'id': "x", 'peer': {'ip': "0.0.0.0", 'port': 80}},
    {'type': 'punch_go', 'id': "x", 'peer': {'ip': "224.0.0.1", 'port': 80}},
    {'type': 'punch_go', 'id': "x", 'peer': {'ip': "127.0.0.1", 'port': 0}},
    {'type': 'punch_go', 'id': "x", 'peer': {'ip': "127.0.0.1", 'port': 70000}},
    {'type': 'punch_go', 'id': "x", 'peer': {'ip': "127.0.0.1", 'port': "80"}},
    {'type': 'punch_go', 'id': "x", 'peer': {'ip': "127.0.0.1", 'port': True}},
    {'type': 'punch_go', 'id': "x", 'peer': {'ip': "127.0.0.1"}},
    {'type': 'punch_go', 'id': "x", 'peer': "127.0.0.1:80"},
    {'type': 'punch_go', 'id': "x" * 65, 'peer': {'ip': "127.0.0.1", 'port': 80}},
    {'type': 'punch_go', 'id': "", 'peer': {'ip': "127.0.0.1", 'port': 80}},
    {'type': 'punch_go', 'id': 5, 'peer': {'ip': "127.0.0.1", 'port': 80}},
    {'type': 'punch_go', 'peer': {'ip': "127.0.0.1", 'port': 80}},
    {'type': 'punch_go', 'id': "x"},
])
async def test_a_punch_go_that_is_not_an_endpoint_is_not_dialed(go, dials):
    srv, server_port = await scripted_server(go_server(go))
    client = PunchClient((IP, server_port), "10.0.0.1", "tok",
                         (IP, dead_port()), echo)
    try:
        assert await client.request(
            Node(2, IP, 1, virtual_ip="10.0.0.2"), b"PING") is None
        assert dials == []       # the peer was never dialed
        assert "10.0.0.2" in client._retry_after and client._expected == {}
    finally:
        await client.stop()
        await close_srv(srv)


@pytest.mark.asyncio
async def test_only_the_named_endpoint_is_dialed_and_only_for_the_window(
        monkeypatch, dials):
    """The peer dials what the server named and nothing else, for no longer
    than the window, then gives up with no socket or task left."""
    monkeypatch.setattr(punch, "PUNCH_WINDOW", 0.7)
    monkeypatch.setattr(punch, "PUNCH_RETRY_INTERVAL", 0.1)
    made = []
    real_socket = stun.reusable_socket
    monkeypatch.setattr(stun, "reusable_socket",
                        lambda *a, **k: made.append(real_socket(*a, **k)) or made[-1])
    refused = dead_port()    # connecting is refused at once, so it retries
    srv, server_port = await scripted_server(go_server(
        {'type': 'punch_go', 'id': "x", 'peer': {'ip': IP, 'port': refused}}))
    client = PunchClient((IP, server_port), "10.0.0.1", "tok",
                         (IP, dead_port()), echo)
    try:
        started = asyncio.get_running_loop().time()
        assert await client.request(
            Node(2, IP, 1, virtual_ip="10.0.0.2"), b"PING") is None
        assert 0.6 <= asyncio.get_running_loop().time() - started < 3
        assert set(dials) == {(IP, refused)}
        assert len(dials) > 1          # it retried
        assert client._expected == {} and client._attempts == {}
    finally:
        await client.stop()
        await close_srv(srv)
    await asyncio.sleep(0.05)
    assert made and all(s.fileno() == -1 for s in made)


# --- Cleanup ---


def punch_tasks():
    return [t for t in asyncio.all_tasks() if not t.done() and
            t.get_coro().__qualname__.startswith(("PunchClient.", "PunchedChannel."))]


@pytest.mark.asyncio
async def test_stop_closes_channels_and_leaves_no_task_or_socket(tmp_path, monkeypatch):
    made = []
    real_socket = stun.reusable_socket
    monkeypatch.setattr(stun, "reusable_socket",
                        lambda *a, **k: made.append(real_socket(*a, **k)) or made[-1])
    async with Lab(tmp_path, monkeypatch) as lab:
        a = await lab.node("a")
        b = await lab.node("b")
        c = await lab.node("c")
        assert punch_tasks()
        await b.stop()
        assert b.punch is None and b.kademlia.punch is None
        # a's and c's ends of b's connections see them close.
        await wait_until(lambda: b.virtual_ip not in a.punch.channels
                         and b.virtual_ip not in c.punch.channels)
        await b.stop()    # twice is harmless
        await a.stop()
        await c.stop()
        assert punch_tasks() == []
        await wait_until(lambda: lab.server.pending_punches == {})
        await asyncio.sleep(0.05)
        assert made and all(s.fileno() == -1 for s in made)


@pytest.mark.asyncio
async def test_stop_in_the_middle_of_a_punch_cancels_it(monkeypatch, dials):
    """Stopping while a punch is waiting for the server's go, and while it is
    dialing the peer, ends both at once."""
    made = []
    real_socket = stun.reusable_socket
    monkeypatch.setattr(stun, "reusable_socket",
                        lambda *a, **k: made.append(real_socket(*a, **k)) or made[-1])
    monkeypatch.setattr(punch, "PUNCH_WINDOW", 30)
    firewall = Firewall()
    await asyncio.sleep(0.05)

    async def silent(reader, writer):
        await reader.read(4096)
        await asyncio.sleep(30)

    silent_srv, silent_port = await scripted_server(silent)
    dialing_srv, dialing_port = await scripted_server(go_server(
        {'type': 'punch_go', 'id': "x", 'peer': {'ip': IP, 'port': firewall.port}}))
    try:
        for server_port, waiting_for in ((silent_port, "the go"),
                                         (dialing_port, "the dial")):
            client = PunchClient((IP, server_port), "10.0.0.1", "tok",
                                 (IP, dead_port()), echo)
            request = asyncio.create_task(
                client.request(Node(2, IP, 1, virtual_ip="10.0.0.2"), b"PING"))
            if waiting_for == "the dial":
                await wait_until(lambda: len(dials) > 0)
            else:
                await wait_until(lambda: client._attempts)
            await asyncio.wait_for(client.stop(), 2)
            assert await asyncio.wait_for(request, 2) is None   # not cancelled
            assert punch_tasks() == [] and client._expected == {}
            assert await client.request(
                Node(2, IP, 1, virtual_ip="10.0.0.2"), b"PING") is None  # stopped
    finally:
        firewall.close()
        for srv in (silent_srv, dialing_srv):
            srv.close()
    await asyncio.sleep(0.05)
    assert made and all(s.fileno() == -1 for s in made)
