"""Data models for the DHCP relay consistency validator.

All DHCP messages handled here are simulated events. This project never
sends or receives real network traffic; it only reasons about event
records that describe what a relay or server observed.
"""
from dataclasses import dataclass
from typing import Optional, Tuple, FrozenSet

DISCOVER = "DISCOVER"
REQUEST = "REQUEST"
OFFER = "OFFER"
ACK = "ACK"
NAK = "NAK"

LEASE_ACTIVE = "active"
LEASE_EXPIRED = "expired"
LEASE_RELEASED = "released"


@dataclass(frozen=True)
class Option82:
    """Simulated DHCP Option 82 (Relay Agent Information).

    circuit_id identifies the access port the client is attached to;
    remote_id usually identifies the relay / access node itself.
    """

    circuit_id: str
    remote_id: str = ""


@dataclass(frozen=True)
class RelayAgent:
    """A DHCP relay agent and the segment it serves.

    address: source IP the relay uses when forwarding to the server.
    giaddr: giaddr value the relay stamps into forwarded packets.
    segment: CIDR of the client segment behind this relay.
    circuit_ids: Option 82 circuit-ids this relay is expected to insert.
    """

    name: str
    address: str
    giaddr: str
    segment: str
    circuit_ids: Tuple[str, ...] = ()


@dataclass(frozen=True)
class AddressPool:
    """Assignable address range for one segment.

    gateway: the giaddr a request must carry to draw from this pool.
    occupied: addresses statically taken (infrastructure, manual use).
    """

    segment: str
    gateway: str
    start: str
    end: str
    occupied: FrozenSet[str] = frozenset()


@dataclass
class Lease:
    mac: str
    ip: str
    segment: str
    state: str = LEASE_ACTIVE
    expires_at: float = 0.0


@dataclass(frozen=True)
class RequestEvent:
    """A simulated client request observed after relay forwarding."""

    mac: str
    xid: int
    giaddr: str
    option82: Option82
    relay_address: str
    message_type: str = DISCOVER
    requested_ip: Optional[str] = None
    timestamp: float = 0.0


@dataclass(frozen=True)
class ResponseEvent:
    """A simulated server response (OFFER/ACK/NAK) routed back via giaddr."""

    xid: int
    mac: str
    message_type: str
    offered_ip: Optional[str]
    giaddr: str
    timestamp: float = 0.0
