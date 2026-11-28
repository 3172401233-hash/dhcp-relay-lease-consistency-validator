"""Core consistency validation for simulated DHCP relay traffic.

The validator consumes relay/pool/lease configuration plus simulated
request and response events, then computes, for every client request:

* the owning relay (which relay *should* serve this client),
* the assignable address from the matching pool,
* the final lease after responses are applied.

It detects duplicate requests, diverging giaddr values, lease renewals,
occupied addresses, conflicting leases and misrouted responses, and
produces affected segments plus recovery steps.
"""
import ipaddress
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .models import (
    ACK,
    DISCOVER,
    LEASE_ACTIVE,
    LEASE_RELEASED,
    NAK,
    OFFER,
    REQUEST,
    AddressPool,
    Lease,
    Option82,
    RelayAgent,
    RequestEvent,
    ResponseEvent,
)

# Finding kinds.
MULTI_RELAY_FORWARD = "multi_relay_forward"
WRONG_GIADDR = "wrong_giaddr"
UNKNOWN_RELAY = "unknown_relay"
ADDRESS_OCCUPIED = "address_occupied"
POOL_EXHAUSTED = "pool_exhausted"
CONFLICTING_LEASES = "conflicting_leases"
RESPONSE_WRONG_SEGMENT = "response_wrong_segment"
RESPONSE_WITHOUT_REQUEST = "response_without_request"

DEFAULT_LEASE_SECONDS = 3600.0


@dataclass
class Finding:
    kind: str
    message: str
    mac: Optional[str] = None
    xid: Optional[int] = None
    segment: Optional[str] = None
    details: dict = field(default_factory=dict)


@dataclass
class RequestOutcome:
    """Computed result for one simulated client request."""

    event: RequestEvent
    owning_relay: Optional[str]
    assignable_ip: Optional[str]
    final_lease: Optional[Lease]
    duplicate: bool = False
    findings: List[Finding] = field(default_factory=list)


@dataclass
class ValidationReport:
    outcomes: List[RequestOutcome] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    conflicting_leases: List[dict] = field(default_factory=list)
    wrong_giaddr: List[dict] = field(default_factory=list)
    affected_segments: List[str] = field(default_factory=list)
    recovery_steps: List[str] = field(default_factory=list)
    lease_db: Dict[str, Lease] = field(default_factory=dict)

    def findings_of(self, kind):
        return [f for f in self.findings if f.kind == kind]


def _iter_pool_addresses(pool):
    start = int(ipaddress.ip_address(pool.start))
    end = int(ipaddress.ip_address(pool.end))
    for value in range(start, end + 1):
        yield str(ipaddress.ip_address(value))


class DHCPRelayConsistencyValidator:
    """Validates relay/giaddr/lease consistency over simulated events."""

    def __init__(self, relays, pools, leases=None, lease_seconds=DEFAULT_LEASE_SECONDS):
        self.relays = list(relays)
        self.pools = list(pools)
        self.lease_seconds = lease_seconds
        self.lease_db = {lease.ip: lease for lease in (leases or [])}
        self._relays_by_address = {r.address: r for r in self.relays}
        self._relays_by_giaddr = {r.giaddr: r for r in self.relays}
        self._pool_by_gateway = {p.gateway: p for p in self.pools}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def validate(self, requests, responses):
        """Process simulated events and return a ValidationReport."""
        report = ValidationReport()
        ordered_requests = sorted(requests, key=lambda e: e.timestamp)
        ordered_responses = sorted(responses, key=lambda e: e.timestamp)

        seen = {}          # (mac, xid) -> first RequestEvent
        tentative = {}     # (mac, xid) -> assignable ip
        outcomes_by_key = {}

        for event in ordered_requests:
            outcome = self._process_request(event, seen, tentative)
            report.outcomes.append(outcome)
            report.findings.extend(outcome.findings)
            outcomes_by_key[(event.mac, event.xid)] = outcome

        for event in ordered_responses:
            findings = self._process_response(event, outcomes_by_key)
            report.findings.extend(findings)

        self._detect_conflicting_leases(report)
        self._summarize(report)
        report.lease_db = dict(self.lease_db)
        return report

    # ------------------------------------------------------------------
    # Request processing
    # ------------------------------------------------------------------
    def _process_request(self, event, seen, tentative):
        outcome = RequestOutcome(
            event=event,
            owning_relay=None,
            assignable_ip=None,
            final_lease=None,
        )
        key = (event.mac, event.xid)
        relay = self._resolve_owning_relay(event, outcome)
        outcome.owning_relay = relay.name if relay else None

        first = seen.get(key)
        if first is not None:
            outcome.duplicate = True
            if (first.giaddr != event.giaddr) or (
                first.relay_address != event.relay_address
            ):
                outcome.findings.append(Finding(
                    kind=MULTI_RELAY_FORWARD,
                    mac=event.mac,
                    xid=event.xid,
                    segment=relay.segment if relay else None,
                    message=(
                        "同一客户端请求 (mac=%s, xid=%s) 被多个 relay 转发: "
                        "%s(giaddr=%s) 与 %s(giaddr=%s)"
                        % (event.mac, event.xid,
                           first.relay_address, first.giaddr,
                           event.relay_address, event.giaddr)
                    ),
                    details={
                        "first_relay": first.relay_address,
                        "first_giaddr": first.giaddr,
                        "second_relay": event.relay_address,
                        "second_giaddr": event.giaddr,
                    },
                ))
            # Retransmission: reuse the address chosen for the first copy.
            outcome.assignable_ip = tentative.get(key)
            return outcome

        seen[key] = event
        outcome.assignable_ip = self._assign_address(event, relay, outcome)
        tentative[key] = outcome.assignable_ip
        return outcome

    def _resolve_owning_relay(self, event, outcome):
        relay = self._relays_by_address.get(event.relay_address)
        if relay is None:
            relay = self._relays_by_giaddr.get(event.giaddr)
        if relay is None:
            for candidate in self.relays:
                if event.option82.circuit_id in candidate.circuit_ids:
                    relay = candidate
                    break
        if relay is None:
            outcome.findings.append(Finding(
                kind=UNKNOWN_RELAY,
                mac=event.mac,
                xid=event.xid,
                message="无法确定归属 relay: relay_address=%s giaddr=%s circuit_id=%s"
                        % (event.relay_address, event.giaddr,
                           event.option82.circuit_id),
            ))
            return None

        if event.giaddr != relay.giaddr:
            outcome.findings.append(Finding(
                kind=WRONG_GIADDR,
                mac=event.mac,
                xid=event.xid,
                segment=relay.segment,
                message=(
                    "giaddr 不一致: 请求携带 giaddr=%s, 但归属 relay %s "
                    "期望 giaddr=%s" % (event.giaddr, relay.name, relay.giaddr)
                ),
                details={
                    "relay": relay.name,
                    "expected_giaddr": relay.giaddr,
                    "actual_giaddr": event.giaddr,
                },
            ))
        return relay

    def _assign_address(self, event, relay, outcome):
        pool = self._pool_by_gateway.get(event.giaddr)
        if pool is None and relay is not None:
            pool = self._pool_by_gateway.get(relay.giaddr)
        if pool is None:
            return None

        # Lease renewal: keep the client's existing address in this segment.
        for lease in self.lease_db.values():
            if (lease.mac == event.mac and lease.segment == pool.segment
                    and lease.state == LEASE_ACTIVE):
                lease.expires_at = event.timestamp + self.lease_seconds
                outcome.final_lease = lease
                return lease.ip

        requested = event.requested_ip
        if requested is not None:
            holder = self.lease_db.get(requested)
            occupied = requested in pool.occupied
            if occupied or (holder is not None and holder.state == LEASE_ACTIVE
                            and holder.mac != event.mac):
                outcome.findings.append(Finding(
                    kind=ADDRESS_OCCUPIED,
                    mac=event.mac,
                    xid=event.xid,
                    segment=pool.segment,
                    message="请求的地址 %s 已被占用, 重新分配" % requested,
                    details={"requested_ip": requested},
                ))
            else:
                return requested

        for candidate in _iter_pool_addresses(pool):
            if candidate in pool.occupied:
                continue
            lease = self.lease_db.get(candidate)
            if lease is not None and lease.state == LEASE_ACTIVE:
                continue
            return candidate

        outcome.findings.append(Finding(
            kind=POOL_EXHAUSTED,
            mac=event.mac,
            xid=event.xid,
            segment=pool.segment,
            message="地址池 %s 已耗尽" % pool.segment,
        ))
        return None

    # ------------------------------------------------------------------
    # Response processing
    # ------------------------------------------------------------------
    def _process_response(self, event, outcomes_by_key):
        findings = []
        outcome = outcomes_by_key.get((event.mac, event.xid))
        if outcome is None:
            findings.append(Finding(
                kind=RESPONSE_WITHOUT_REQUEST,
                mac=event.mac,
                xid=event.xid,
                message="响应 (xid=%s) 没有匹配的请求" % event.xid,
            ))
            return findings

        request = outcome.event
        relay = self._relays_by_address.get(request.relay_address)
        expected_giaddr = relay.giaddr if relay else request.giaddr
        if event.giaddr != expected_giaddr:
            segment = relay.segment if relay else None
            findings.append(Finding(
                kind=RESPONSE_WRONG_SEGMENT,
                mac=event.mac,
                xid=event.xid,
                segment=segment,
                message=(
                    "响应 giaddr=%s 与归属 relay 期望的 giaddr=%s 不一致, "
                    "DHCPOFFER 可能被送到错误网段"
                    % (event.giaddr, expected_giaddr)
                ),
                details={
                    "expected_giaddr": expected_giaddr,
                    "actual_giaddr": event.giaddr,
                },
            ))

        if event.message_type == NAK:
            return findings

        if event.message_type in (OFFER, ACK):
            ip = event.offered_ip or outcome.assignable_ip
            if ip is None:
                return findings
            holder = self.lease_db.get(ip)
            if (holder is not None and holder.state == LEASE_ACTIVE
                    and holder.mac != event.mac):
                findings.append(Finding(
                    kind=CONFLICTING_LEASES,
                    mac=event.mac,
                    xid=event.xid,
                    message="地址 %s 已租给 %s, 无法确认给 %s"
                            % (ip, holder.mac, event.mac),
                    details={"ip": ip, "holder": holder.mac},
                ))
                return findings
            if event.message_type == ACK:
                segment = None
                pool = self._pool_by_gateway.get(event.giaddr)
                if pool is not None:
                    segment = pool.segment
                elif relay is not None:
                    segment = relay.segment
                lease = Lease(
                    mac=event.mac,
                    ip=ip,
                    segment=segment or "",
                    state=LEASE_ACTIVE,
                    expires_at=event.timestamp + self.lease_seconds,
                )
                self.lease_db[ip] = lease
                outcome.final_lease = lease
        return findings

    # ------------------------------------------------------------------
    # Cross-checks and summary
    # ------------------------------------------------------------------
    def _detect_conflicting_leases(self, report):
        by_mac = {}
        for lease in self.lease_db.values():
            if lease.state == LEASE_ACTIVE:
                by_mac.setdefault(lease.mac, []).append(lease)
        for mac, leases in sorted(by_mac.items()):
            if len(leases) > 1:
                ips = sorted(l.ip for l in leases)
                segments = sorted({l.segment for l in leases})
                report.findings.append(Finding(
                    kind=CONFLICTING_LEASES,
                    mac=mac,
                    message="MAC %s 持有多个活动租约: %s" % (mac, ", ".join(ips)),
                    details={"ips": ips, "segments": segments},
                ))

    def _summarize(self, report):
        conflicting = []
        wrong_giaddr = []
        segments = set()
        steps = []

        for finding in report.findings:
            if finding.kind == CONFLICTING_LEASES:
                conflicting.append({
                    "mac": finding.mac,
                    "message": finding.message,
                    "details": finding.details,
                })
                for seg in finding.details.get("segments", []):
                    segments.add(seg)
            elif finding.kind in (WRONG_GIADDR, RESPONSE_WRONG_SEGMENT):
                wrong_giaddr.append({
                    "mac": finding.mac,
                    "xid": finding.xid,
                    "message": finding.message,
                    "details": finding.details,
                })
                if finding.segment:
                    segments.add(finding.segment)
            elif finding.kind in (MULTI_RELAY_FORWARD, ADDRESS_OCCUPIED,
                                  POOL_EXHAUSTED):
                if finding.segment:
                    segments.add(finding.segment)

        if any(f.kind == MULTI_RELAY_FORWARD for f in report.findings):
            steps.append(
                "排查接入端口与 relay 的对应关系, 确保同一客户端请求只经一个 "
                "relay 转发; 核对两台 relay 的 Option 82 circuit-id 配置")
        if wrong_giaddr:
            steps.append(
                "校正相关 relay 的 giaddr/Option 82 配置, 使回程 DHCPOFFER "
                "按归属 relay 的 giaddr 路由到正确网段")
        if conflicting:
            steps.append(
                "释放冲突 MAC 的冗余租约, 仅保留与归属 relay 网段一致的租约, "
                "并在租约数据库中清理重复记录")
        if any(f.kind == ADDRESS_OCCUPIED for f in report.findings):
            steps.append(
                "将已占用地址在地址池中标记为保留, 或回收冲突地址后重新分配")
        if any(f.kind == POOL_EXHAUSTED for f in report.findings):
            steps.append("扩容耗尽的地址池或缩短租约时长以回收地址")
        if any(f.kind == UNKNOWN_RELAY for f in report.findings):
            steps.append("将未知 relay 的地址/giaddr/circuit-id 登记到 relay 清单")

        report.conflicting_leases = conflicting
        report.wrong_giaddr = wrong_giaddr
        report.affected_segments = sorted(segments)
        report.recovery_steps = steps
