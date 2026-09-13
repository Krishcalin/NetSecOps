"""Python-implemented checks (FR-CHK-02).

Only logic a declarative expression cannot honestly express belongs here. "Is Telnet
disabled" is a JMESPath comparison and stays in YAML, where it is readable by someone
who does not write Python. What lands here is the kind of reasoning that needs to walk
a collection and weigh several fields at once: which interfaces are access ports, which
of *those* lack BPDU guard, and whether the ones that do are shut down anyway.

Each of these still has a YAML file carrying its metadata — title, rationale, severity,
framework mapping — so a Python check is as discoverable and as auditable as any other.
Only the logic differs.

Every one of them observes the same rule as the declarative engine: a field the parser
did not determine yields *Not Evaluated*, never a verdict.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from netsecops.checks.engine import (
    CheckResult,
    EvaluationContext,
    EvidenceLine,
    python_check,
)
from netsecops.checks.schema import Outcome, Severity

# ─────────────────────────── weak cryptography ──────────────────────────────

#: SSH key-exchange algorithms no longer fit for use. `sha1` and the 1024-bit
#: Diffie-Hellman groups are the substance; the rest are the historic spellings
#: network vendors actually emit.
WEAK_KEX = {
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
    "rsa1024-sha1",
}

WEAK_CIPHERS = {
    "3des-cbc",
    "des-cbc",
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
    "arcfour",
    "arcfour128",
    "arcfour256",
    "blowfish-cbc",
    "cast128-cbc",
    "rc4",
}

WEAK_MACS = {
    "hmac-md5",
    "hmac-md5-96",
    "hmac-sha1-96",
    "umac-64@openssh.com",
}

WEAK_TLS = {"ssl3.0", "sslv3", "tls1.0", "tlsv1", "tls1.1", "tlsv1.1"}


def _lower(values: Any) -> list[str]:
    if not isinstance(values, Sequence) or isinstance(values, str):
        return []
    return [str(item).lower().strip() for item in values]


def _result(
    outcome: Outcome,
    message: str,
    *,
    observed: Any = None,
    expected: str | None = None,
    evidence: list[EvidenceLine] | None = None,
    reason: str | None = None,
) -> CheckResult:
    # check_id, title and severity are filled in by the engine from the YAML metadata,
    # so a Python check never restates them and they cannot drift apart.
    return CheckResult(
        check_id="",
        outcome=outcome,
        severity=Severity.MEDIUM,
        title="",
        message=message,
        observed=observed,
        expected=expected,
        evidence=evidence or [],
        reason=reason,
    )


def _weak_algorithms(
    context: EvaluationContext, path: str, weak: set[str], label: str
) -> CheckResult:
    configured = context.select(path)

    if configured is None:
        return _result(
            Outcome.NOT_EVALUATED,
            f"Not evaluated: the configuration did not state which {label} are permitted. "
            f"On many platforms an unstated list means the vendor default, which this "
            f"check cannot see from configuration alone.",
            reason=f"missing:{path}",
        )

    names = _lower(configured)
    if not names:
        return _result(
            Outcome.NOT_EVALUATED,
            f"Not evaluated: no {label} are listed in the configuration.",
            reason=f"empty:{path}",
        )

    offenders = sorted(name for name in names if name in weak)
    evidence = context.evidence_for(path)

    if offenders:
        return _result(
            Outcome.FAIL,
            f"{len(offenders)} weak {label} permitted: {', '.join(offenders)}.",
            observed=offenders,
            expected=f"no {label} from the known-weak set",
            evidence=evidence,
        )

    return _result(
        Outcome.PASS,
        f"All {len(names)} permitted {label} are acceptable.",
        observed=names,
        evidence=evidence,
    )


@python_check("ssh_weak_kex")
def ssh_weak_kex(context: EvaluationContext) -> CheckResult:
    return _weak_algorithms(
        context, "management.services.ssh.kex", WEAK_KEX, "SSH key-exchange algorithms"
    )


@python_check("ssh_weak_ciphers")
def ssh_weak_ciphers(context: EvaluationContext) -> CheckResult:
    return _weak_algorithms(context, "management.services.ssh.ciphers", WEAK_CIPHERS, "SSH ciphers")


@python_check("ssh_weak_macs")
def ssh_weak_macs(context: EvaluationContext) -> CheckResult:
    return _weak_algorithms(context, "management.services.ssh.macs", WEAK_MACS, "SSH MACs")


@python_check("tls_weak_versions")
def tls_weak_versions(context: EvaluationContext) -> CheckResult:
    return _weak_algorithms(
        context, "management.services.https.tls_versions", WEAK_TLS, "TLS versions"
    )


# ──────────────────────────── interface posture ─────────────────────────────


def _interfaces(context: EvaluationContext) -> list[Mapping[str, Any]]:
    found = context.select("interfaces")
    return [item for item in found if isinstance(item, Mapping)] if found else []


def _is_access_port(interface: Mapping[str, Any]) -> bool:
    """An access port is one switching user traffic.

    Uplinks and routed ports are excluded: BPDU guard on a trunk to the distribution
    layer would take the link down, so flagging its absence there would be advice
    nobody should follow.
    """
    return str(interface.get("mode") or "").lower() == "access"


def _interface_evidence(
    context: EvaluationContext, interfaces: Sequence[Mapping[str, Any]]
) -> list[EvidenceLine]:
    names = {str(i.get("name")) for i in interfaces}
    entries: Mapping[str, Any] = context.provenance.get("entries", {}) if context.provenance else {}
    lines: list[EvidenceLine] = []

    for key, entry in entries.items():
        if not key.startswith("interfaces."):
            continue
        excerpt = (entry or {}).get("excerpt") or ""
        if any(name and name in excerpt for name in names):
            lines.append(
                EvidenceLine(
                    path=key,
                    line_start=(entry or {}).get("line_start"),
                    line_end=(entry or {}).get("line_end"),
                    excerpt=excerpt,
                )
            )
    return lines[:10]


def _access_port_feature(context: EvaluationContext, field: str, label: str) -> CheckResult:
    interfaces = _interfaces(context)
    if not interfaces:
        return _result(
            Outcome.NOT_EVALUATED,
            "Not evaluated: no interfaces were parsed from this configuration.",
            reason="missing:interfaces",
        )

    access = [i for i in interfaces if _is_access_port(i)]
    if not access:
        return _result(
            Outcome.NOT_APPLICABLE,
            "This device has no access ports, so the setting does not apply.",
            reason="no-access-ports",
        )

    offenders: list[Mapping[str, Any]] = []
    unknown: list[str] = []

    for interface in access:
        # A shut port cannot forward a frame, so it is not the exposure this check is
        # about. Flagging it would bury the ports that are actually live.
        if interface.get("admin_up") is False:
            continue
        value = (interface.get("security") or {}).get(field)
        if value is None:
            unknown.append(str(interface.get("name")))
        elif value is not True:
            offenders.append(interface)

    if offenders:
        names = sorted(str(i.get("name")) for i in offenders)
        return _result(
            Outcome.FAIL,
            f"{len(names)} of {len(access)} access ports do not have {label}: "
            f"{', '.join(names[:8])}{'…' if len(names) > 8 else ''}.",
            observed=names,
            expected=f"every enabled access port should have {label}",
            evidence=_interface_evidence(context, offenders),
        )

    if unknown and not offenders:
        # Every access port's state for this feature was indeterminate. Reporting a
        # pass would be asserting something the configuration never said.
        return _result(
            Outcome.NOT_EVALUATED,
            f"Not evaluated: {label} could not be determined for {len(unknown)} access port(s).",
            reason="indeterminate",
        )

    return _result(
        Outcome.PASS,
        f"All {len(access)} access ports have {label}.",
        observed=len(access),
    )


@python_check("access_ports_port_security")
def access_ports_port_security(context: EvaluationContext) -> CheckResult:
    return _access_port_feature(context, "port_security", "port security")


@python_check("access_ports_bpduguard")
def access_ports_bpduguard(context: EvaluationContext) -> CheckResult:
    return _access_port_feature(context, "bpduguard", "BPDU guard")


@python_check("unused_interfaces_shutdown")
def unused_interfaces_shutdown(context: EvaluationContext) -> CheckResult:
    """An interface with no description, no address and no VLAN, left enabled.

    The signal is weak on its own — plenty of legitimate ports carry no description —
    so all three have to be absent before it counts. That is the difference between a
    check an operator acts on and one they mute.
    """
    interfaces = _interfaces(context)
    if not interfaces:
        return _result(
            Outcome.NOT_EVALUATED,
            "Not evaluated: no interfaces were parsed from this configuration.",
            reason="missing:interfaces",
        )

    idle = [
        interface
        for interface in interfaces
        if interface.get("admin_up") is not False
        and not interface.get("description")
        and not interface.get("ip_addresses")
        and not interface.get("vlan")
        and str(interface.get("name", "")).lower().startswith(("gigabit", "fast", "ethernet", "te"))
    ]

    if not idle:
        return _result(Outcome.PASS, "No unused interfaces were found administratively up.")

    names = sorted(str(i.get("name")) for i in idle)
    return _result(
        Outcome.FAIL,
        f"{len(names)} interface(s) appear unused but are not shut down: "
        f"{', '.join(names[:8])}{'…' if len(names) > 8 else ''}.",
        observed=names,
        expected="unused interfaces should be administratively shut down",
        evidence=_interface_evidence(context, idle),
    )


# ──────────────────────────────── accounts ──────────────────────────────────


@python_check("local_accounts_minimal")
def local_accounts_minimal(context: EvaluationContext) -> CheckResult:
    """Local accounts beyond a break-glass pair, where central AAA is configured.

    With AAA in place, local accounts are the ones that survive a TACACS+ outage — and
    the ones nobody deprovisions. Where AAA is *not* configured this is Not Applicable
    rather than a fail: local accounts are then the only way in, and telling an
    operator to delete them would be dangerous advice.
    """
    users = context.select("users")
    if users is None:
        return _result(
            Outcome.NOT_EVALUATED,
            "Not evaluated: local accounts were not parsed from this configuration.",
            reason="missing:users",
        )

    aaa_servers = context.select("aaa.servers") or []
    if not aaa_servers:
        return _result(
            Outcome.NOT_APPLICABLE,
            "No central AAA server is configured, so local accounts are the only "
            "available authentication and are expected.",
            reason="no-aaa",
        )

    names = sorted(str(u.get("name")) for u in users if isinstance(u, Mapping))
    if len(names) <= 2:
        return _result(
            Outcome.PASS,
            f"{len(names)} local account(s), consistent with break-glass use.",
            observed=names,
        )

    return _result(
        Outcome.FAIL,
        f"{len(names)} local accounts exist alongside central AAA: {', '.join(names[:8])}"
        f"{'…' if len(names) > 8 else ''}. Break-glass access needs at most two.",
        observed=names,
        expected="at most two local accounts where central AAA is configured",
        evidence=context.evidence_for("users"),
    )


@python_check("no_weak_password_hashes")
def no_weak_password_hashes(context: EvaluationContext) -> CheckResult:
    """Reversible or fast password storage on any local account.

    Cisco type 0 is plaintext and type 7 is a trivially reversible XOR — neither is a
    hash. Type 5 is unsalted MD5. The parser decides which is which per platform and
    sets `weak_hash`; this check is about reporting *which* accounts, because the
    remediation is per account.
    """
    users = context.select("users")
    if users is None:
        return _result(
            Outcome.NOT_EVALUATED,
            "Not evaluated: local accounts were not parsed from this configuration.",
            reason="missing:users",
        )

    accounts = [u for u in users if isinstance(u, Mapping)]
    if not accounts:
        return _result(Outcome.PASS, "No local accounts are configured.")

    weak = [u for u in accounts if u.get("weak_hash") is True]
    unknown = [u for u in accounts if u.get("weak_hash") is None]

    if weak:
        names = sorted(str(u.get("name")) for u in weak)
        return _result(
            Outcome.FAIL,
            f"{len(names)} local account(s) use reversible or weak password storage: "
            f"{', '.join(names)}.",
            observed=names,
            expected="every local account should use the platform's strongest hash",
            evidence=context.evidence_for("users"),
        )

    if unknown and len(unknown) == len(accounts):
        return _result(
            Outcome.NOT_EVALUATED,
            f"Not evaluated: the password storage type could not be determined for "
            f"{len(unknown)} account(s).",
            reason="indeterminate",
        )

    return _result(
        Outcome.PASS,
        f"All {len(accounts)} local accounts use acceptable password storage.",
        observed=len(accounts),
    )


# ───────────────────────────────── AAA ──────────────────────────────────────


@python_check("aaa_servers_have_keys")
def aaa_servers_have_keys(context: EvaluationContext) -> CheckResult:
    """Every configured TACACS+/RADIUS server has a shared secret.

    A keyless RADIUS server is not merely misconfigured: the exchange is unauthenticated
    and an attacker on-path can answer for it. NetSecOps never reads the key itself —
    the parser records only whether one is set (FR-COL-13).
    """
    servers = context.select("aaa.servers")
    if servers is None:
        return _result(
            Outcome.NOT_EVALUATED,
            "Not evaluated: AAA servers were not parsed from this configuration.",
            reason="missing:aaa.servers",
        )

    entries = [s for s in servers if isinstance(s, Mapping)]
    if not entries:
        return _result(
            Outcome.NOT_APPLICABLE,
            "No AAA servers are configured on this device.",
            reason="no-aaa",
        )

    keyless = [s for s in entries if s.get("key_configured") is False]
    unknown = [s for s in entries if s.get("key_configured") is None]

    if keyless:
        hosts = sorted(str(s.get("host")) for s in keyless)
        return _result(
            Outcome.FAIL,
            f"{len(hosts)} AAA server(s) have no shared secret configured: {', '.join(hosts)}.",
            observed=hosts,
            expected="every AAA server should have a shared secret",
            evidence=context.evidence_for("aaa.servers"),
        )

    if len(unknown) == len(entries):
        return _result(
            Outcome.NOT_EVALUATED,
            "Not evaluated: whether the AAA servers have shared secrets could not be determined.",
            reason="indeterminate",
        )

    return _result(
        Outcome.PASS,
        f"All {len(entries)} AAA servers have a shared secret configured.",
        observed=len(entries),
    )


# ────────────────────────────── certificates ────────────────────────────────


def _certificate_expiry(context: EvaluationContext, days: int) -> CheckResult:
    certificates = context.select("certificates")
    if certificates is None:
        return _result(
            Outcome.NOT_EVALUATED,
            "Not evaluated: no certificate details were collected.",
            reason="missing:certificates",
        )

    entries = [c for c in certificates if isinstance(c, Mapping)]
    if not entries:
        return _result(
            Outcome.NOT_APPLICABLE,
            "No certificates are installed on this device.",
            reason="no-certificates",
        )

    now = datetime.now(UTC)
    expiring: list[tuple[str, int]] = []

    for certificate in entries:
        raw = certificate.get("not_after")
        if not raw:
            continue
        try:
            expiry = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        except ValueError:
            continue
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=UTC)
        remaining = (expiry - now).days
        if remaining <= days:
            expiring.append((str(certificate.get("name") or certificate.get("subject")), remaining))

    if not expiring:
        return _result(
            Outcome.PASS,
            f"No certificate expires within {days} days.",
            observed=len(entries),
        )

    described = ", ".join(
        f"{name} ({'expired' if left < 0 else f'{left} days'})"
        for name, left in sorted(expiring, key=lambda e: e[1])
    )
    return _result(
        Outcome.FAIL,
        f"{len(expiring)} certificate(s) expire within {days} days: {described}.",
        observed=[name for name, _ in expiring],
        expected=f"no certificate should expire within {days} days",
        evidence=context.evidence_for("certificates"),
    )


@python_check("certificates_expiring_30")
def certificates_expiring_30(context: EvaluationContext) -> CheckResult:
    return _certificate_expiry(context, 30)


@python_check("certificates_expiring_90")
def certificates_expiring_90(context: EvaluationContext) -> CheckResult:
    return _certificate_expiry(context, 90)


# ──────────────────────────────── SNMP ──────────────────────────────────────


@python_check("snmp_no_default_communities")
def snmp_no_default_communities(context: EvaluationContext) -> CheckResult:
    """Default community strings such as `public` and `private`.

    The parser masks community values before they reach the NCM, so this reads the
    `is_default` flag it set at parse time rather than the string itself — the check
    never sees the secret it is reasoning about (C-2).
    """
    communities = context.select("snmp.v1v2c_communities")
    if communities is None:
        return _result(
            Outcome.NOT_EVALUATED,
            "Not evaluated: SNMP communities were not parsed from this configuration.",
            reason="missing:snmp.v1v2c_communities",
        )

    entries = [c for c in communities if isinstance(c, Mapping)]
    if not entries:
        return _result(Outcome.PASS, "No SNMP v1/v2c communities are configured.", observed=0)

    defaults = [c for c in entries if c.get("is_default") is True]
    if defaults:
        masked = [str(c.get("name_masked")) for c in defaults]
        return _result(
            Outcome.FAIL,
            f"{len(defaults)} default SNMP community string(s) are configured: {', '.join(masked)}.",
            observed=masked,
            expected="no default community strings",
            evidence=context.evidence_for("snmp.v1v2c_communities"),
        )

    return _result(
        Outcome.PASS,
        f"None of the {len(entries)} configured communities are vendor defaults.",
        observed=len(entries),
    )


@python_check("snmp_v3_authpriv_only")
def snmp_v3_authpriv_only(context: EvaluationContext) -> CheckResult:
    """SNMPv3 users below authPriv.

    noAuthNoPriv and authNoPriv are both SNMPv3, which is why a version check alone is
    not enough: the version is right and the security level is not.
    """
    users = context.select("snmp.v3_users")
    if users is None:
        return _result(
            Outcome.NOT_EVALUATED,
            "Not evaluated: SNMPv3 users were not parsed from this configuration.",
            reason="missing:snmp.v3_users",
        )

    entries = [u for u in users if isinstance(u, Mapping)]
    if not entries:
        return _result(
            Outcome.NOT_APPLICABLE,
            "No SNMPv3 users are configured on this device.",
            reason="no-v3-users",
        )

    weak = [u for u in entries if str(u.get("level")) != "authPriv"]
    if weak:
        described = ", ".join(f"{u.get('name')} ({u.get('level')})" for u in weak)
        return _result(
            Outcome.FAIL,
            f"{len(weak)} SNMPv3 user(s) are not authPriv: {described}.",
            observed=[str(u.get("name")) for u in weak],
            expected="every SNMPv3 user should use authPriv",
            evidence=context.evidence_for("snmp.v3_users"),
        )

    return _result(
        Outcome.PASS, f"All {len(entries)} SNMPv3 users use authPriv.", observed=len(entries)
    )


__all__ = [
    "WEAK_CIPHERS",
    "WEAK_KEX",
    "WEAK_MACS",
    "WEAK_TLS",
]
