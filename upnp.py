"""Optional UPnP port mapping.

If the `miniupnpc` package is importable, UPnPMapping asks the local router
(an Internet Gateway Device) to forward a TCP port to this host, so peers
outside the NAT can dial it directly, and removes the mapping again on
close(). Nothing here is required: without the package, or with a router
that has no UPnP or refuses the mapping, open() just returns False and the
node carries on (the relay in relay.py is the fallback for a node nobody
can dial).

miniupnpc is blocking, so its calls run in a worker thread, each bounded by
UPNP_TIMEOUT.
"""

import asyncio
import threading
from typing import Optional

try:
    import miniupnpc
except ImportError:
    miniupnpc = None

# How long open() and close() wait on the router before giving up.
UPNP_TIMEOUT = 10
UPNP_DESCRIPTION = "p2p-net"


class UPnPMapping:
    """A TCP port mapping on the local router: the same port number outside
    and inside, forwarded to this host's LAN address.

    open() makes it, close() removes it. The mapping is permanent on the
    router until removed (the miniupnpc Python API sets no lease time), so a
    process that dies without close() leaves it behind.
    """

    def __init__(self, port: int):
        self.port = port
        # The router's external address, if it reported one.
        self.external_ip: Optional[str] = None
        self._upnp = None   # the miniupnpc.UPnP handle, once a mapping exists
        self._task = None   # the worker-thread call that is making it
        # close() and the worker thread meet here: a mapping that is made
        # after close() has given up waiting for it is removed by the worker.
        self._lock = threading.Lock()
        self._closed = False

    async def open(self) -> bool:
        """Try to map the port; True if the router now forwards it.

        If the router has not answered within UPNP_TIMEOUT this returns
        False, but the attempt keeps going in its thread; close() removes
        the mapping if it succeeds in time, and the thread removes it itself
        if it succeeds after close() gave up.
        """
        if miniupnpc is None:
            return False
        self._task = asyncio.ensure_future(asyncio.to_thread(self._map))
        try:
            await asyncio.wait_for(asyncio.shield(self._task), UPNP_TIMEOUT)
        except asyncio.TimeoutError:
            print(f"UPnP: the router did not answer in {UPNP_TIMEOUT}s; "
                  f"carrying on without a port mapping")
            return False
        except Exception as e:
            print(f"UPnP port mapping for port {self.port} unavailable: {e}")
            return False
        return True

    def _map(self):
        # Runs in a worker thread.
        upnp = miniupnpc.UPnP()
        upnp.discover()
        upnp.selectigd()
        # A refused mapping is reported as False by some miniupnpc versions
        # and raised as an exception by others.
        if not upnp.addportmapping(self.port, "TCP", upnp.lanaddr, self.port,
                                   UPNP_DESCRIPTION, ""):
            raise RuntimeError("the router refused the mapping")
        with self._lock:
            closed = self._closed
            if not closed:
                self._upnp = upnp
        if closed:
            try:
                upnp.deleteportmapping(self.port, "TCP")
            except Exception:
                pass
            return
        try:
            self.external_ip = upnp.externalipaddress()
        except Exception:
            pass  # the mapping exists; its external address is only for show

    async def close(self):
        """Remove the mapping, if there is one. Never raises (except for
        cancellation): a router that has gone away just leaves it behind."""
        if self._task is not None:
            # An attempt that outlived open()'s timeout: give it one more
            # UPNP_TIMEOUT to finish so the mapping it made can be removed.
            try:
                await asyncio.wait_for(asyncio.shield(self._task),
                                       UPNP_TIMEOUT)
            except Exception:
                pass
            self._task = None
        with self._lock:
            self._closed = True
            upnp, self._upnp = self._upnp, None
        if upnp is None:
            return
        try:
            removed = await asyncio.wait_for(
                asyncio.to_thread(upnp.deleteportmapping, self.port, "TCP"),
                UPNP_TIMEOUT)
        except Exception as e:
            print(f"UPnP: could not remove the mapping for port {self.port}: "
                  f"{e or type(e).__name__}")
            return
        if removed:
            print(f"UPnP: removed the mapping for port {self.port}")
        else:
            print(f"UPnP: the router did not remove the mapping for port "
                  f"{self.port}")
