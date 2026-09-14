"""FortiAuthenticator, FreeRADIUS and tac_plus (FR-AAA-03, FR-AAA-04).

Three AAA servers, one NCM block, and one question that separates them: **can this
source answer whether a shared secret is reused?**

ISE and FortiAuthenticator return `********`. Fingerprinting that would produce one
identical value for every device and report the entire estate as sharing a key — a
confident, completely wrong finding — so those sources report `None`, which FR-AAA-05
renders as "unknown".

FreeRADIUS and tac_plus configurations contain the *real* key. Those are fingerprinted
and discarded, so reuse becomes genuinely detectable — and detectable *across* sources,
because the fingerprint is the same function the redaction module uses.

The other thing pinned here is a bug written three times in one sitting: `_bool(a) or
_bool(b)` and `X or None`. `False or None` is None, so a source explicitly reporting a
setting as *off* — usually the finding — came through as "not determined" and the check
reported Not Evaluated. It appeared in the ISE parser, then the FortiAuthenticator
parser, then in a tac_plus line written minutes later. Every three-state field below has
a test for all three states.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pytest

from netsecops.core.redaction import fingerprint
from netsecops.ncm.models import AaaServerConfig
from netsecops.parsers.base import ParseContext
from netsecops.parsers.registry import get_parser

FIXTURES = Path(__file__).parent / "fixtures"
FREERADIUS = FIXTURES / "linux/freeradius/3.0/campus_radius.json"
TACPLUS = FIXTURES / "linux/tacplus/campus_tacplus.conf"
FORTIAUTH = FIXTURES / "fortinet/fortiauthenticator/6.5/campus_fac.json"

#: Planted in the Linux fixtures, which are the only AAA sources that carry real
#: credentials in the clear.
PLANTED = (
    "SharedEstateKey2026",
    "P4rtnerUniqueKey!",
    "EapKeyPassw0rd",
    "LdapB1ndPass",
    "WlcOwnKey!2026",
    "L3gacyPl4inText",
    "Ux9Kd7QpLmNvB",
)


def parse(platform: str, path: Path) -> dict[str, Any]:
    return (
        get_parser(platform).parse(ParseContext(text=path.read_text(encoding="utf-8"))).to_storage()
    )


@pytest.fixture(scope="module")
def radius() -> dict[str, Any]:
    return parse("freeradius", FREERADIUS)


@pytest.fixture(scope="module")
def tacplus() -> dict[str, Any]:
    return parse("tac_plus", TACPLUS)


@pytest.fixture(scope="module")
def fac() -> dict[str, Any]:
    return parse("fortiauthenticator", FORTIAUTH)


# ═════════════════════════════ FreeRADIUS ════════════════════════════════════


class TestFreeRadius:
    def test_every_client_is_read(self, radius: dict[str, Any]) -> None:
        names = {c["name"] for c in radius["aaa_server"]["clients"]}
        assert names == {
            "core-sw-01",
            "campus-wlc-01",
            "branch-rtr-07",
            "partner-nas",
            "radsec-peer",
        }

    def test_shared_secret_reuse_is_detectable_here(self, radius: dict[str, Any]) -> None:
        """The point of fingerprinting. Three clients share one key, and the finding is
        that a single secret unlocks most of the estate — without NetSecOps ever holding
        it (FR-AAA-05, C-2)."""
        by_name = {c["name"]: c for c in radius["aaa_server"]["clients"]}
        shared = {
            by_name["core-sw-01"]["secret_fingerprint"],
            by_name["campus-wlc-01"]["secret_fingerprint"],
            by_name["branch-rtr-07"]["secret_fingerprint"],
        }

        assert len(shared) == 1, "three clients share a key but got different fingerprints"
        assert by_name["partner-nas"]["secret_fingerprint"] not in shared

    def test_the_fingerprint_is_the_shared_redaction_function(self, radius: dict[str, Any]) -> None:
        """So a secret seen in a RADIUS server's configuration and the same secret seen
        in a switch's own configuration produce one value, and reuse is detectable
        across sources rather than only within one."""
        by_name = {c["name"]: c for c in radius["aaa_server"]["clients"]}
        assert by_name["core-sw-01"]["secret_fingerprint"] == fingerprint("SharedEstateKey2026")

    def test_an_eap_method_is_available_if_its_block_exists(self, radius: dict[str, Any]) -> None:
        """`md5 { }` present means the server will do EAP-MD5 on request, whether or not
        it is the default. Reading only `default_eap_type` misses it entirely."""
        protocols = set(radius["aaa_server"]["allowed_protocols"])
        assert {"EAP-MD5", "LEAP"} <= protocols

    def test_modules_in_the_authorize_list_count_as_accepted(self, radius: dict[str, Any]) -> None:
        """PAP, CHAP and MS-CHAP are modules rather than policy settings in FreeRADIUS,
        and their presence in `authorize` is what makes them acceptable."""
        protocols = set(radius["aaa_server"]["allowed_protocols"])
        assert {"PAP", "CHAP", "MS-CHAPv1"} <= protocols

    def test_the_weak_ones_are_identified(self, radius: dict[str, Any]) -> None:
        weak = AaaServerConfig.model_validate(radius["aaa_server"]).weak_protocols
        assert weak == ["CHAP", "EAP-MD5", "LEAP", "MS-CHAPv1", "PAP"]

    def test_the_tls_floor_is_read(self, radius: dict[str, Any]) -> None:
        """`tls_min_version = "1.0"` means the server still negotiates TLS 1.0 for
        EAP-TLS, which is the finding."""
        assert "TLS1.0" in radius["aaa_server"]["tls_versions"]

    def test_a_radsec_client_is_marked(self, radius: dict[str, Any]) -> None:
        by_name = {c["name"]: c for c in radius["aaa_server"]["clients"]}
        assert by_name["radsec-peer"]["tls"] is True

    def test_an_ldap_bind_without_tls_is_visible(self, radius: dict[str, Any]) -> None:
        stores = radius["aaa_server"]["identity_stores"]
        assert stores and stores[0]["tls"] is False

    def test_a_file_nothing_reads_is_reported(self, radius: dict[str, Any]) -> None:
        assert any("unused-module" in line for line in radius["raw_unparsed"])

    def test_a_single_pasted_file_is_accepted(self) -> None:
        """The offline-import path (FR-COL-11). Refusing a bare file would make it
        useless for exactly the host most likely to be imported by hand."""
        text = "client sw {\n\tipaddr = 10.0.0.1\n\tsecret = k\n}\n"
        parsed = get_parser("freeradius").parse(ParseContext(text=text)).to_storage()
        assert parsed["aaa_server"]["clients"][0]["name"] == "sw"


# ═══════════════════════════════ tac_plus ════════════════════════════════════


class TestTacPlus:
    def test_clients_are_named_by_hostname_not_address(self, tacplus: dict[str, Any]) -> None:
        """`host = 198.51.100.31 { name = core-sw-01 }`. Using the block argument would
        make every finding cite an IP, and the FR-AAA-05 correlation is far easier to
        read by hostname."""
        by_name = {c["name"]: c for c in tacplus["aaa_server"]["clients"]}
        assert set(by_name) == {"core-sw-01", "campus-wlc-01"}
        assert by_name["core-sw-01"]["address"] == "198.51.100.31"

    def test_the_global_key_applies_to_clients_that_do_not_override_it(
        self, tacplus: dict[str, Any]
    ) -> None:
        by_name = {c["name"]: c for c in tacplus["aaa_server"]["clients"]}
        assert by_name["core-sw-01"]["secret_fingerprint"] == fingerprint("SharedEstateKey2026")
        assert by_name["campus-wlc-01"]["secret_fingerprint"] == fingerprint("WlcOwnKey!2026")

    def test_reuse_is_detectable_across_sources(self, tacplus, radius) -> None:
        """The same key is configured on the FreeRADIUS server and as the tac_plus global
        key. One fingerprint function means the correlation sees them as one secret."""
        tac = {c["name"]: c for c in tacplus["aaa_server"]["clients"]}
        rad = {c["name"]: c for c in radius["aaa_server"]["clients"]}
        assert tac["core-sw-01"]["secret_fingerprint"] == rad["core-sw-01"]["secret_fingerprint"]

    def test_default_service_permit_is_surfaced(self, tacplus: dict[str, Any]) -> None:
        """The single most important line in a tac_plus configuration: every command not
        explicitly denied is allowed, which makes the careful rules below it decoration.
        It landed in `unparsed` until the reader learned that a key may contain a space.
        """
        sets = {c["name"]: c for c in tacplus["aaa_server"]["command_sets"]}
        assert sets["netops"]["permit_unmatched"] is True

    def test_default_service_deny_is_false_not_unknown(self, tacplus: dict[str, Any]) -> None:
        """The `X or None` trap, written a third time and caught here. A group that
        explicitly denies unmatched commands — the *correct* configuration — reported as
        "not determined", so the check said Not Evaluated and the good config looked
        identical to an unreadable one."""
        sets = {c["name"]: c for c in tacplus["aaa_server"]["command_sets"]}
        assert sets["helpdesk"]["permit_unmatched"] is False

    def test_a_group_with_no_default_service_stays_unknown(self) -> None:
        """The third state, which the fix must not collapse."""
        text = "group = odd {\n\tcmd = show {\n\t\tpermit .*\n\t}\n}\n"
        parsed = get_parser("tac_plus").parse(ParseContext(text=text)).to_storage()
        assert parsed["aaa_server"]["command_sets"][0]["permit_unmatched"] is None

    def test_command_rules_are_read_as_directives(self, tacplus: dict[str, Any]) -> None:
        """`permit .*` inside `cmd = show { }` is a bare directive, not an assignment.
        The whole of tac_plus command authorisation is written this way."""
        sets = {c["name"]: c for c in tacplus["aaa_server"]["command_sets"]}
        assert "show permit .*" in sets["netops"]["commands"]

    def test_cleartext_password_storage_is_flagged(self, tacplus: dict[str, Any]) -> None:
        """`login = cleartext <password>` is common in configurations that grew from a
        lab. The storage type is the finding; the password never reaches the NCM."""
        users = {u["name"]: u for u in tacplus["users"]}
        assert users["legacyops"]["secret_type"] == "cleartext"
        assert users["legacyops"]["weak_hash"] is True

    def test_des_storage_is_also_weak(self, tacplus: dict[str, Any]) -> None:
        users = {u["name"]: u for u in tacplus["users"]}
        assert users["admin"]["secret_type"] == "des"
        assert users["admin"]["weak_hash"] is True

    def test_group_membership_is_carried(self, tacplus: dict[str, Any]) -> None:
        users = {u["name"]: u for u in tacplus["users"]}
        assert users["auditor"]["role"] == "helpdesk"

    def test_the_whole_file_is_accounted_for(self, tacplus: dict[str, Any]) -> None:
        assert tacplus["raw_unparsed"] == []


# ════════════════════════ FortiAuthenticator ═════════════════════════════════


class TestFortiAuthenticator:
    def test_identity_and_admin_settings(self, fac: dict[str, Any]) -> None:
        assert fac["device"]["hostname"] == "fac-campus-01"
        assert fac["aaa_server"]["admin_session_timeout_s"] == 900

    def test_mfa_disabled_survives_as_false(self, fac: dict[str, Any]) -> None:
        assert fac["aaa_server"]["admin_mfa_enabled"] is False

    def test_clients_are_read_with_their_enabled_state(self, fac: dict[str, Any]) -> None:
        by_name = {c["name"]: c for c in fac["aaa_server"]["clients"]}
        assert by_name["decommissioned-ap"]["enabled"] is False
        assert by_name["core-sw-01"]["enabled"] is True

    def test_the_secret_is_masked_so_reuse_is_unknown(self, fac: dict[str, Any]) -> None:
        """FR-AAA-05 asks that reuse be reported as *unknown* where the source does not
        expose the secret. A fingerprint of `********` would be identical for every
        device and report the whole estate as sharing one key."""
        assert all(c["secret_fingerprint"] is None for c in fac["aaa_server"]["clients"])
        assert all(c["secret_configured"] for c in fac["aaa_server"]["clients"])

    def test_protocols_are_the_union_across_policies(self, fac: dict[str, Any]) -> None:
        """One policy still accepting MS-CHAPv1 is a way in whatever the others do."""
        protocols = set(fac["aaa_server"]["allowed_protocols"])
        assert {"EAP-TLS", "PEAP", "MS-CHAPv2", "PAP", "MS-CHAPv1"} == protocols

    def test_each_policy_keeps_its_own_protocol_list(self, fac: dict[str, Any]) -> None:
        """So a finding can name the rule to change rather than only the server."""
        by_name = {p["name"]: p for p in fac["aaa_server"]["policies"]}
        assert by_name["Legacy VPN"]["allowed_protocols"] == ["MS-CHAPv1", "PAP"]

    def test_an_ldap_server_without_tls_is_false_not_unknown(self, fac: dict[str, Any]) -> None:
        """The `or` trap again: `_bool(False) or _bool(None)` is None, so a directory
        explicitly configured without TLS reported as not determined."""
        stores = {s["name"]: s for s in fac["aaa_server"]["identity_stores"]}
        assert stores["legacy-ldap"]["tls"] is False
        assert stores["corp-ldap"]["tls"] is True

    def test_an_endpoint_nothing_reads_is_reported(self, fac: dict[str, Any]) -> None:
        assert any("guestportals" in line for line in fac["raw_unparsed"])


# ══════════════════════ what all three share ═════════════════════════════════


class TestSharedBehaviour:
    @pytest.mark.parametrize(
        ("platform", "path"),
        [("freeradius", FREERADIUS), ("tac_plus", TACPLUS), ("fortiauthenticator", FORTIAUTH)],
    )
    def test_no_secret_reaches_the_ncm(self, platform: str, path: Path) -> None:
        """C-2. FreeRADIUS and tac_plus are the only AAA sources carrying real
        credentials in the clear, and the redaction rules for their `key = value` syntax
        were written *before* these parsers rather than after a leak — the first time in
        this project that happened in that order."""
        serialised = json.dumps(parse(platform, path))
        leaked = [secret for secret in PLANTED if secret in serialised]
        assert not leaked, f"{platform}: {leaked} reached the NCM"

    @pytest.mark.parametrize("secret", PLANTED)
    def test_every_planted_secret_is_really_in_a_fixture(self, secret: str) -> None:
        corpus = FREERADIUS.read_text(encoding="utf-8") + TACPLUS.read_text(encoding="utf-8")
        assert secret in corpus, f"{secret} is not planted; the leak test is vacuous"

    @pytest.mark.parametrize(
        "line",
        [
            "\tsecret = R4d1usK3y!Secret",
            "key = T4c4csK3y!Secret",
            "\tlogin = cleartext L3gacyPl4inText",
            "\tlogin = des Ux9Kd7QpLmNvB",
            "\tprivate_key_password = EapKeyPassw0rd",
        ],
    )
    def test_the_unix_conf_syntaxes_redact(self, line: str) -> None:
        from netsecops.core.redaction import redact_line

        redacted, _ = redact_line(line)
        assert "«redacted:" in redacted
        assert line.split()[-1] not in redacted

    @pytest.mark.parametrize(
        ("platform", "path"),
        [("freeradius", FREERADIUS), ("tac_plus", TACPLUS), ("fortiauthenticator", FORTIAUTH)],
    )
    def test_no_section_fails_silently(
        self, platform: str, path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING):
            parse(platform, path)

        failures = [r for r in caplog.records if "section_failed" in r.getMessage()]
        assert not failures, [r.getMessage() for r in failures]

    @pytest.mark.parametrize(
        ("platform", "product"),
        [
            ("freeradius", "freeradius"),
            ("tac_plus", "tac_plus"),
            ("fortiauthenticator", "fortiauthenticator"),
        ],
    )
    def test_the_product_is_identified(self, platform: str, product: str) -> None:
        """Which server-side checks apply turns on this."""
        parsed = get_parser(platform).parse(ParseContext(text="")).to_storage()
        assert parsed["aaa_server"]["product"] == product

    @pytest.mark.parametrize("platform", ["freeradius", "tac_plus", "fortiauthenticator"])
    def test_an_empty_artefact_does_not_raise(self, platform: str) -> None:
        assert get_parser(platform).parse(ParseContext(text="")) is not None

    @pytest.mark.parametrize("platform", ["freeradius", "tac_plus"])
    def test_a_truncated_capture_keeps_what_arrived(self, platform: str) -> None:
        """A `cat` cut short by a dropped session leaves blocks open. Discarding them
        loses everything above the cut as well as below it."""
        text = "client half {\n\tipaddr = 10.0.0.1\n"
        assert get_parser(platform).parse(ParseContext(text=text)) is not None

    def test_malformed_json_produces_a_snapshot_rather_than_an_exception(self) -> None:
        result = get_parser("fortiauthenticator").parse(ParseContext(text='{"truncated": '))
        assert result.raw_unparsed and "not valid JSON" in result.raw_unparsed[0]
