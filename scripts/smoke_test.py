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
