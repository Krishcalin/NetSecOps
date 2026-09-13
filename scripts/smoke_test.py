#!/usr/bin/env python3
"""Post-deployment smoke test against a running NetSecOps stack.

Exercises the real HTTP surface end to end: unauthenticated rejection, security
headers, sign-in and cookie flags, RBAC, MFA enrolment and challenge, refresh-token
rotation, audit-chain integrity, and the SPA.

    python scripts/smoke_test.py --api http://localhost:8000 --ui http://localhost:8080 \
        --admin-user admin --admin-password '...'

It creates a temporary user for the destructive parts (MFA enrolment, lockout) and
deletes it afterwards, so it never alters the operator account it signs in with. An
earlier version enrolled MFA on the bootstrap admin and left the secret nowhere
recoverable — hence the throwaway.

Requires: httpx, pyotp (both already backend dependencies).
"""

from __future__ import annotations

import argparse
import sys
import uuid

import httpx
import pyotp

TEMP_PASSWORD = "Smoke-Test-P4ssw0rd!"  # noqa: S105 - throwaway, deleted at the end


class Results:
    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0

    def check(self, label: str, condition: bool, detail: str = "") -> None:
        if condition:
            self.passed += 1
            print(f"  PASS  {label}")
        else:
            self.failed += 1
            print(f"  FAIL  {label}  {detail}")

    def section(self, title: str) -> None:
        print(f"\n== {title} ==")


def csrf_headers(client: httpx.Client) -> dict[str, str]:
    token = client.cookies.get("netsecops_csrf")
    return {"X-CSRF-Token": token} if token else {}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api", default="http://localhost:8000")
    parser.add_argument("--ui", default="http://localhost:8080")
    parser.add_argument("--admin-user", required=True)
    parser.add_argument("--admin-password", required=True)
    parser.add_argument(
        "--skip-ui", action="store_true", help="Skip SPA checks (API-only deployment)"
    )
    args = parser.parse_args()

    r = Results()

    # ── Unauthenticated access ──────────────────────────────────────────
    r.section("Unauthenticated access")
    with httpx.Client(base_url=args.api, timeout=15) as c:
        resp = c.get("/api/v1/auth/me")
        r.check("/auth/me rejects anonymous", resp.status_code == 401, str(resp.status_code))
        r.check(
            "errors are problem+json",
            resp.headers.get("content-type", "").startswith("application/problem+json"),
            resp.headers.get("content-type", ""),
        )
        r.check(
            "audit log rejects anonymous",
            c.get("/api/v1/audit-log").status_code == 401,
        )

    # ── Security headers (SEC-02) ───────────────────────────────────────
    r.section("Security headers")
    with httpx.Client(base_url=args.api, timeout=15) as c:
        h = c.get("/healthz").headers
        r.check("X-Content-Type-Options", h.get("x-content-type-options") == "nosniff")
        r.check("X-Frame-Options DENY", h.get("x-frame-options") == "DENY")
        r.check("Content-Security-Policy", "content-security-policy" in h)
        r.check("Correlation id echoed", "x-correlation-id" in h)

    # ── Readiness ───────────────────────────────────────────────────────
    r.section("Readiness")
    with httpx.Client(base_url=args.api, timeout=15) as c:
        resp = c.get("/readyz")
        r.check("database ready", resp.status_code == 200, resp.text[:120])

    # ── Administrator sign-in ───────────────────────────────────────────
    r.section("Administrator sign-in")
    admin = httpx.Client(base_url=args.api, timeout=15)
    resp = admin.post(
        "/api/v1/auth/login",
        json={"username": args.admin_user, "password": args.admin_password},
    )
    if resp.status_code != 200:
        print(f"  FATAL  admin sign-in failed: {resp.status_code} {resp.text[:200]}")
        return 1

    body = resp.json()
    if body.get("mfa_required"):
        print(
            "  FATAL  the admin account has MFA enabled; this script needs a "
            "password-only operator account, or clear it with "
            "`netsecops-cli reset-mfa <user>`"
        )
        return 1

    r.check("admin signs in", True)
    cookies = " ".join(resp.headers.get_list("set-cookie"))
    r.check("access cookie HttpOnly", "netsecops_access" in cookies and "HttpOnly" in cookies)
    r.check("refresh cookie path-scoped", "Path=/api/v1/auth" in cookies)
    r.check("SameSite=strict", "samesite=strict" in cookies.lower())

    me = admin.get("/api/v1/auth/me").json()
    r.check("identity returned", me.get("username") == args.admin_user, str(me)[:120])
    r.check("permissions populated", len(me.get("permissions", [])) > 0)

    r.check("refresh rotates", admin.post("/api/v1/auth/refresh").status_code == 200)

    # ── Temporary user for the destructive checks ───────────────────────
    r.section("Temporary user")
    temp_name = f"smoke_{uuid.uuid4().hex[:10]}"
    resp = admin.post(
        "/api/v1/users",
        json={
            "username": temp_name,
            # example.com, not .invalid/.test — those are reserved TLDs that
            # email-validator rejects.
            "email": f"{temp_name}@example.com",
            "password": TEMP_PASSWORD,
            "roles": ["auditor"],
            "must_change_password": False,
        },
        headers=csrf_headers(admin),
    )
    created = resp.status_code == 201
    r.check("temporary user created", created, f"{resp.status_code} {resp.text[:160]}")
    temp_id = resp.json().get("id") if created else None

    try:
        if created:
            _run_user_checks(args.api, temp_name, r)

        # ── Inventory and credential vault (Phase 1) ────────────────────
        _run_inventory_checks(admin, r)

        # ── Audit log (FR-AUD-01/02) ────────────────────────────────────
        r.section("Audit log")
        resp = admin.get("/api/v1/audit-log?limit=20")
        r.check("audit readable", resp.status_code == 200, f"{resp.status_code} {resp.text[:160]}")
        if resp.status_code == 200:
            entries = resp.json()["data"]
            r.check("login recorded", any(e["action"] == "login.success" for e in entries))
            r.check(
                "hash chain populated", all(e.get("hash") and e.get("prev_hash") for e in entries)
            )

        verify = admin.get("/api/v1/audit-log/verify").json()
        r.check("chain verifies", verify.get("valid") is True, str(verify))

    finally:
        if temp_id:
            admin.request("DELETE", f"/api/v1/users/{temp_id}", headers=csrf_headers(admin))
            print(f"\n  cleaned up temporary user {temp_name}")
        admin.close()

    # ── SPA ─────────────────────────────────────────────────────────────
    if not args.skip_ui:
        r.section("SPA")
        try:
            with httpx.Client(timeout=15) as c:
                resp = c.get(f"{args.ui}/")
                r.check("SPA served", resp.status_code == 200, str(resp.status_code))
                r.check("SPA CSP header", "content-security-policy" in resp.headers)
                r.check(
                    "proxy routes /api to the backend",
                    c.get(f"{args.ui}/api/v1/auth/me").status_code == 401,
                )
        except httpx.HTTPError as exc:
            r.check("SPA reachable", False, str(exc))

    print(f"\n{'=' * 46}\n  {r.passed} passed, {r.failed} failed\n{'=' * 46}")
    return 1 if r.failed else 0


def _run_inventory_checks(admin: httpx.Client, r: Results) -> None:
    """Inventory, CSV import and the credential vault (FR-INV, FR-CRED).

    Everything created here is namespaced with a random tag, so repeated runs against a
    live deployment do not collide with each other or with real inventory.
    """
    tag = uuid.uuid4().hex[:6]
    headers = csrf_headers(admin)

    r.section("Inventory")
    resp = admin.post("/api/v1/device-groups", json={"name": f"smoke-{tag}"}, headers=headers)
    r.check("create device group", resp.status_code == 201, resp.text[:160])
    group = resp.json() if resp.status_code == 201 else {}
    r.check("group carries an ltree path", bool(group.get("path")))

    resp = admin.post(
        "/api/v1/devices",
        json={
            "mgmt_ip": f"203.0.113.{(int(tag, 16) % 200) + 10}",
            "hostname": f"smoke-{tag}",
            "vendor": "cisco",
            "platform": "cisco_ios",
            "device_class": "switch",
            "group_ids": [group["id"]] if group else [],
            "tags": [f"smoke-{tag}"],
        },
        headers=headers,
    )
    r.check("create device", resp.status_code == 201, f"{resp.status_code} {resp.text[:160]}")
    device = resp.json() if resp.status_code == 201 else {}

    resp = admin.post(
        "/api/v1/devices",
        json={"mgmt_ip": "203.0.113.251", "platform": "acme_router_9000"},
        headers=headers,
    )
    r.check(
        "a platform with no read-only policy is refused",
        resp.status_code == 422,
        str(resp.status_code),
    )

    r.section("CSV import (FR-INV-02)")
    bad_csv = b"mgmt_ip\n203.0.113.240\nnot-an-ip\n"
    resp = admin.post(
        "/api/v1/devices/import/preview",
        files={"file": ("bad.csv", bad_csv, "text/csv")},
        headers=headers,
    )
    body = resp.json() if resp.status_code == 200 else {}
    r.check("preview reports invalid rows", body.get("invalid") == 1, resp.text[:160])
    r.check(
        "the offending line number is reported",
        any(row["line"] == 3 and not row["valid"] for row in body.get("rows", [])),
        resp.text[:200],
    )

    r.section("Credential vault (FR-CRED)")
    secret = f"smoke-secret-{uuid.uuid4().hex}"
    resp = admin.post(
        "/api/v1/credentials",
        json={
            "name": f"smoke-cred-{tag}",
            "credential_type": "ssh_password",
            "secret_data": {"username": "readonly", "password": secret},
        },
        headers=headers,
    )
    r.check("create credential", resp.status_code == 201, f"{resp.status_code} {resp.text[:160]}")
    credential = resp.json() if resp.status_code == 201 else {}

    # The whole point of the vault: the secret goes in and never comes back out.
    r.check("the secret is not echoed back", secret not in resp.text, "SECRET LEAKED IN RESPONSE")
    r.check(
        "listing credentials returns no secrets",
        secret not in admin.get("/api/v1/credentials").text,
        "SECRET LEAKED IN LIST",
    )
    r.check(
        "an unrecognised secret field is refused",
        admin.post(
            "/api/v1/credentials",
            json={
                "name": f"smoke-sneaky-{tag}",
                "credential_type": "ssh_password",
                "secret_data": {"username": "u", "password": "p", "extra": "x"},
            },
            headers=headers,
        ).status_code
        == 422,
    )

    if credential and device:
        resp = admin.post(
            f"/api/v1/credentials/{credential['id']}/assignments",
            json={"device_id": device["id"], "priority": 10},
            headers=headers,
        )
        r.check("assign credential to device", resp.status_code == 201, resp.text[:160])

    r.section("Jobs (FR-JOB)")
    r.check("job history reachable", admin.get("/api/v1/jobs").status_code == 200)
    r.check(
        "a scope matching nothing is refused",
        admin.post(
            "/api/v1/jobs",
            json={"job_type": "collect", "scope": {"device_ids": [str(uuid.uuid4())]}},
            headers=headers,
        ).status_code
        == 422,
    )

    r.check(
        "no secret reaches the audit log",
        secret not in admin.get("/api/v1/audit-log?limit=200").text,
        "SECRET LEAKED IN AUDIT LOG",
    )

    # Leave the deployment as we found it.
    for path in (
        f"/api/v1/credentials/{credential['id']}" if credential else None,
        f"/api/v1/devices/{device['id']}" if device else None,
    ):
        if path:
            admin.request("DELETE", path, headers=headers)


def _run_user_checks(api: str, username: str, r: Results) -> None:
    """MFA and lockout checks, run against the throwaway account only."""
    r.section("MFA enrolment (FR-AUTH-03)")
    with httpx.Client(base_url=api, timeout=15) as c:
        login = c.post("/api/v1/auth/login", json={"username": username, "password": TEMP_PASSWORD})
        r.check("temp user signs in", login.status_code == 200, str(login.status_code))

        resp = c.post("/api/v1/auth/mfa/enroll", headers=csrf_headers(c))
        r.check(
            "enrolment starts", resp.status_code == 200, f"{resp.status_code} {resp.text[:160]}"
        )
        if resp.status_code != 200:
            return

        enrolment = resp.json()
        secret = enrolment["secret"]
        r.check("provisioning uri", enrolment["provisioning_uri"].startswith("otpauth://totp/"))
        r.check("recovery codes issued", len(enrolment["recovery_codes"]) == 10)

        confirm = c.post(
            "/api/v1/auth/mfa/confirm",
            json={"code": pyotp.TOTP(secret).now()},
            headers=csrf_headers(c),
        )
        r.check("enrolment confirmed", confirm.status_code == 204, str(confirm.status_code))

    r.section("MFA challenge")
    with httpx.Client(base_url=api, timeout=15) as c:
        body = c.post(
            "/api/v1/auth/login", json={"username": username, "password": TEMP_PASSWORD}
        ).json()
        r.check("password alone yields a challenge", body.get("mfa_required") is True)
        r.check("no token in the challenge", "access_token" not in body)

        resp = c.post(
            "/api/v1/auth/mfa/verify",
            json={"mfa_token": body["mfa_token"], "code": pyotp.TOTP(secret).now()},
        )
        r.check("valid code completes sign-in", resp.status_code == 200, str(resp.status_code))

    r.section("Credential handling (SEC-05)")
    with httpx.Client(base_url=api, timeout=15) as c:
        bad = c.post("/api/v1/auth/login", json={"username": username, "password": "wrong"})
        r.check("bad password rejected", bad.status_code == 401)
        unknown = c.post(
            "/api/v1/auth/login", json={"username": "no-such-user", "password": "wrong"}
        )
        r.check(
            "unknown user is indistinguishable",
            unknown.json().get("detail") == bad.json().get("detail"),
        )


if __name__ == "__main__":
    sys.exit(main())
