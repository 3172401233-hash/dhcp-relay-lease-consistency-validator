"""Unit tests for the DHCP relay consistency validator.

All DHCP messages in these tests are simulated event records; no real
network traffic is generated.
"""
import unittest

from dhcp_relay_validator import (
    ACK,
    DISCOVER,
    OFFER,
    REQUEST,
    AddressPool,
    DHCPRelayConsistencyValidator,
    Lease,
    Option82,
    RelayAgent,
    RequestEvent,
    ResponseEvent,
)
from dhcp_relay_validator.validator import (
    ADDRESS_OCCUPIED,
    CONFLICTING_LEASES,
    MULTI_RELAY_FORWARD,
    POOL_EXHAUSTED,
    RESPONSE_WRONG_SEGMENT,
    WRONG_GIADDR,
)

MAC_A = "aa:bb:cc:00:00:01"
MAC_B = "aa:bb:cc:00:00:02"


def make_relays():
    return [
        RelayAgent(
            name="relay-1",
            address="10.0.0.2",
            giaddr="10.0.0.1",
            segment="10.0.0.0/24",
            circuit_ids=("eth0/1", "eth0/2"),
        ),
        RelayAgent(
            name="relay-2",
            address="10.1.0.2",
            giaddr="10.1.0.1",
            segment="10.1.0.0/24",
            circuit_ids=("eth1/1", "eth1/2"),
        ),
    ]


def make_pools():
    return [
        AddressPool(
            segment="10.0.0.0/24",
            gateway="10.0.0.1",
            start="10.0.0.100",
            end="10.0.0.110",
        ),
        AddressPool(
            segment="10.1.0.0/24",
            gateway="10.1.0.1",
            start="10.1.0.100",
            end="10.1.0.101",
        ),
    ]


def discover(mac, xid, relay, circuit, ts, requested_ip=None, giaddr=None):
    return RequestEvent(
        mac=mac,
        xid=xid,
        giaddr=giaddr if giaddr is not None else relay.giaddr,
        option82=Option82(circuit_id=circuit, remote_id=relay.name),
        relay_address=relay.address,
        message_type=DISCOVER,
        requested_ip=requested_ip,
        timestamp=ts,
    )


class HappyPathTest(unittest.TestCase):
    def test_single_relay_full_handshake(self):
        relays = make_relays()
        validator = DHCPRelayConsistencyValidator(make_relays(), make_pools())
        req = discover(MAC_A, 1001, relays[0], "eth0/1", ts=1.0)
        responses = [
            ResponseEvent(1001, MAC_A, OFFER, "10.0.0.100", "10.0.0.1", 2.0),
            ResponseEvent(1001, MAC_A, ACK, "10.0.0.100", "10.0.0.1", 3.0),
        ]
        report = validator.validate([req], responses)

        self.assertEqual(report.findings, [])
        self.assertEqual(report.affected_segments, [])
        outcome = report.outcomes[0]
        self.assertEqual(outcome.owning_relay, "relay-1")
        self.assertEqual(outcome.assignable_ip, "10.0.0.100")
        self.assertIsNotNone(outcome.final_lease)
        self.assertEqual(outcome.final_lease.ip, "10.0.0.100")
        self.assertEqual(outcome.final_lease.segment, "10.0.0.0/24")


class DuplicateRequestTest(unittest.TestCase):
    def test_retransmission_same_relay_reuses_address(self):
        relays = make_relays()
        validator = DHCPRelayConsistencyValidator(make_relays(), make_pools())
        requests = [
            discover(MAC_A, 2001, relays[0], "eth0/1", ts=1.0),
            discover(MAC_A, 2001, relays[0], "eth0/1", ts=2.0),
        ]
        report = validator.validate(requests, [])

        self.assertEqual(len(report.outcomes), 2)
        self.assertFalse(report.outcomes[0].duplicate)
        self.assertTrue(report.outcomes[1].duplicate)
        self.assertEqual(report.outcomes[0].assignable_ip, "10.0.0.100")
        self.assertEqual(report.outcomes[1].assignable_ip, "10.0.0.100")
        self.assertEqual(report.findings_of(MULTI_RELAY_FORWARD), [])

    def test_same_request_forwarded_by_two_relays(self):
        relays = make_relays()
        validator = DHCPRelayConsistencyValidator(make_relays(), make_pools())
        requests = [
            discover(MAC_A, 3001, relays[0], "eth0/1", ts=1.0),
            discover(MAC_A, 3001, relays[1], "eth1/1", ts=1.5),
        ]
        report = validator.validate(requests, [])

        findings = report.findings_of(MULTI_RELAY_FORWARD)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].details["first_giaddr"], "10.0.0.1")
        self.assertEqual(findings[0].details["second_giaddr"], "10.1.0.1")
        self.assertIn("10.1.0.0/24", report.affected_segments)
        self.assertTrue(any("relay" in s for s in report.recovery_steps))


class Option82ChangeTest(unittest.TestCase):
    def test_option82_port_change_flags_conflicting_leases(self):
        relays = make_relays()
        existing = [
            Lease(mac=MAC_A, ip="10.0.0.100", segment="10.0.0.0/24",
                  expires_at=5000.0),
        ]
        validator = DHCPRelayConsistencyValidator(
            make_relays(), make_pools(), leases=existing)
        # Client reappears behind relay-2 with a different circuit-id,
        # and the server ACKs a second address in the other segment.
        req = discover(MAC_A, 4001, relays[1], "eth1/2", ts=10.0)
        responses = [
            ResponseEvent(4001, MAC_A, ACK, "10.1.0.100", "10.1.0.1", 11.0),
        ]
        report = validator.validate([req], responses)

        self.assertEqual(report.outcomes[0].owning_relay, "relay-2")
        self.assertEqual(report.outcomes[0].assignable_ip, "10.1.0.100")
        conflicts = report.findings_of(CONFLICTING_LEASES)
        self.assertTrue(conflicts)
        self.assertEqual(conflicts[-1].details["ips"],
                         ["10.0.0.100", "10.1.0.100"])
        self.assertEqual(report.affected_segments,
                         ["10.0.0.0/24", "10.1.0.0/24"])
        self.assertTrue(report.conflicting_leases)
        self.assertTrue(any("冗余租约" in s for s in report.recovery_steps))


class RenewalTest(unittest.TestCase):
    def test_renewal_keeps_existing_address(self):
        relays = make_relays()
        existing = [
            Lease(mac=MAC_A, ip="10.0.0.105", segment="10.0.0.0/24",
                  expires_at=100.0),
        ]
        validator = DHCPRelayConsistencyValidator(
            make_relays(), make_pools(), leases=existing)
        req = RequestEvent(
            mac=MAC_A,
            xid=5001,
            giaddr="10.0.0.1",
            option82=Option82(circuit_id="eth0/1", remote_id="relay-1"),
            relay_address="10.0.0.2",
            message_type=REQUEST,
            requested_ip="10.0.0.105",
            timestamp=50.0,
        )
        report = validator.validate([req], [])

        outcome = report.outcomes[0]
        self.assertEqual(outcome.assignable_ip, "10.0.0.105")
        self.assertEqual(outcome.final_lease.ip, "10.0.0.105")
        self.assertGreater(outcome.final_lease.expires_at, 100.0)
        self.assertEqual(report.findings, [])


class OccupiedAddressTest(unittest.TestCase):
    def test_requested_address_occupied_by_other_mac(self):
        relays = make_relays()
        existing = [
            Lease(mac=MAC_B, ip="10.0.0.100", segment="10.0.0.0/24",
                  expires_at=5000.0),
        ]
        validator = DHCPRelayConsistencyValidator(
            make_relays(), make_pools(), leases=existing)
        req = discover(MAC_A, 6001, relays[0], "eth0/1", ts=1.0,
                       requested_ip="10.0.0.100")
        report = validator.validate([req], [])

        findings = report.findings_of(ADDRESS_OCCUPIED)
        self.assertEqual(len(findings), 1)
        self.assertEqual(report.outcomes[0].assignable_ip, "10.0.0.101")
        self.assertIn("10.0.0.0/24", report.affected_segments)

    def test_statically_occupied_pool_address_skipped(self):
        relays = make_relays()
        pools = make_pools()
        pools[0] = AddressPool(
            segment="10.0.0.0/24",
            gateway="10.0.0.1",
            start="10.0.0.100",
            end="10.0.0.102",
            occupied=frozenset({"10.0.0.100"}),
        )
        validator = DHCPRelayConsistencyValidator(make_relays(), pools)
        req = discover(MAC_A, 6002, relays[0], "eth0/1", ts=1.0)
        report = validator.validate([req], [])
        self.assertEqual(report.outcomes[0].assignable_ip, "10.0.0.101")


class LeaseContentionTest(unittest.TestCase):
    def test_two_clients_compete_for_last_pool_address(self):
        relays = make_relays()
        pools = make_pools()
        # Shrink relay-2's pool to a single address.
        pools[1] = AddressPool(
            segment="10.1.0.0/24",
            gateway="10.1.0.1",
            start="10.1.0.100",
            end="10.1.0.100",
        )
        validator = DHCPRelayConsistencyValidator(make_relays(), pools)
        requests = [
            discover(MAC_A, 7001, relays[1], "eth1/1", ts=1.0),
            discover(MAC_B, 7002, relays[1], "eth1/2", ts=2.0),
        ]
        responses = [
            ResponseEvent(7001, MAC_A, ACK, "10.1.0.100", "10.1.0.1", 3.0),
            ResponseEvent(7002, MAC_B, ACK, "10.1.0.100", "10.1.0.1", 4.0),
        ]
        report = validator.validate(requests, responses)

        # Both requests initially select the only free address...
        self.assertEqual(report.outcomes[0].assignable_ip, "10.1.0.100")
        self.assertEqual(report.outcomes[1].assignable_ip, "10.1.0.100")
        # ...but the second ACK loses the race and is flagged.
        conflicts = report.findings_of(CONFLICTING_LEASES)
        self.assertTrue(any(f.mac == MAC_B for f in conflicts))
        active = [l for l in report.lease_db.values() if l.state == "active"]
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0].mac, MAC_A)

    def test_pool_exhaustion_reported(self):
        relays = make_relays()
        pools = make_pools()
        pools[1] = AddressPool(
            segment="10.1.0.0/24",
            gateway="10.1.0.1",
            start="10.1.0.100",
            end="10.1.0.100",
        )
        existing = [
            Lease(mac=MAC_B, ip="10.1.0.100", segment="10.1.0.0/24",
                  expires_at=5000.0),
        ]
        validator = DHCPRelayConsistencyValidator(
            make_relays(), pools, leases=existing)
        req = discover(MAC_A, 7003, relays[1], "eth1/1", ts=1.0)
        report = validator.validate([req], [])

        self.assertIsNone(report.outcomes[0].assignable_ip)
        self.assertEqual(len(report.findings_of(POOL_EXHAUSTED)), 1)
        self.assertTrue(any("扩容" in s for s in report.recovery_steps))


class WrongGiaddrTest(unittest.TestCase):
    def test_request_giaddr_mismatch(self):
        relays = make_relays()
        validator = DHCPRelayConsistencyValidator(make_relays(), make_pools())
        req = discover(MAC_A, 8001, relays[0], "eth0/1", ts=1.0,
                       giaddr="10.1.0.1")
        report = validator.validate([req], [])

        findings = report.findings_of(WRONG_GIADDR)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].details["expected_giaddr"], "10.0.0.1")
        self.assertEqual(findings[0].details["actual_giaddr"], "10.1.0.1")
        self.assertIn("10.0.0.0/24", report.affected_segments)
        self.assertTrue(report.wrong_giaddr)

    def test_response_routed_to_wrong_segment(self):
        relays = make_relays()
        validator = DHCPRelayConsistencyValidator(make_relays(), make_pools())
        req = discover(MAC_A, 8002, relays[0], "eth0/1", ts=1.0)
        responses = [
            ResponseEvent(8002, MAC_A, OFFER, "10.0.0.100", "10.1.0.1", 2.0),
        ]
        report = validator.validate([req], responses)

        findings = report.findings_of(RESPONSE_WRONG_SEGMENT)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].details["expected_giaddr"], "10.0.0.1")
        self.assertIn("10.0.0.0/24", report.affected_segments)
        self.assertTrue(any("giaddr" in s for s in report.recovery_steps))


if __name__ == "__main__":
    unittest.main()
