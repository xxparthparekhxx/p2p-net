import asyncio
import ast
import json
import os
import resource
import sys

import pytest

from introduction_server import IntroductionServer, parse_args

IP = "127.0.0.1"
SCRIPT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "introduction_server.py")
MEMORY_CAP = 256 * 1024 * 1024


def _cap_memory():
    # Address-space cap for the child: the old eager set(hosts()) of a /8
    # needs over 2 GB and dies with MemoryError under it.
    resource.setrlimit(resource.RLIMIT_AS, (MEMORY_CAP, MEMORY_CAP))


async def _join(port, listening_port):
    reader, writer = await asyncio.open_connection(IP, port)
    writer.write(json.dumps({'listening_ip': IP,
                             'listening_port': listening_port}).encode())
    await writer.drain()
    response = json.loads((await asyncio.wait_for(reader.read(4096), 10)).decode())
    writer.close()
    await writer.wait_closed()
    return response


@pytest.mark.asyncio
async def test_server_starts_under_256mb_and_assigns_sequential_ips():
    """`python introduction_server.py` actually runs main() (the __main__
    guard), starts under a 256 MB address-space cap, binds the --host given
    (127.0.0.1) and hands out 10.0.0.1, 10.0.0.2, ... in order."""
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-u", SCRIPT, "--host", IP, "--port", "0",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        preexec_fn=_cap_memory,
    )
    try:
        line = (await asyncio.wait_for(proc.stdout.readline(), 20)).decode()
        assert "serving on" in line, line
        host, port = ast.literal_eval(line.split("serving on", 1)[1].strip())
        assert host == IP

        ips = [(await _join(port, 9000 + i))['virtual_ip'] for i in range(3)]
        assert ips == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
        assert proc.returncode is None  # still serving
    finally:
        if proc.returncode is None:
            proc.kill()
        await proc.wait()


def test_default_host_is_loopback():
    args = parse_args([])
    assert args.host == "127.0.0.1"
    assert args.port == 8888
    assert parse_args(["--host", "0.0.0.0", "--port", "0"]).host == "0.0.0.0"


def test_allocation_is_lazy_sequential_and_reuses_released_ips():
    server = IntroductionServer()
    # Nothing is materialized up front: the pool is a counter plus a set.
    assert server.released_ips == set()
    assert [server.assign_virtual_ip() for _ in range(3)] == [
        "10.0.0.1", "10.0.0.2", "10.0.0.3"]

    server.release_virtual_ip("10.0.0.2")
    assert server.assign_virtual_ip() == "10.0.0.2"
    assert server.assign_virtual_ip() == "10.0.0.4"
    with pytest.raises(ValueError):
        server.release_virtual_ip("10.0.0.9")  # never assigned
    server.release_virtual_ip("10.0.0.1")
    with pytest.raises(ValueError):
        server.release_virtual_ip("10.0.0.1")  # already released


def test_small_network_is_exhausted_without_network_or_broadcast():
    server = IntroductionServer("192.168.5.0/30")
    assert [server.assign_virtual_ip() for _ in range(2)] == [
        "192.168.5.1", "192.168.5.2"]
    with pytest.raises(Exception, match="No available IPs"):
        server.assign_virtual_ip()
    server.release_virtual_ip("192.168.5.1")
    assert server.assign_virtual_ip() == "192.168.5.1"
