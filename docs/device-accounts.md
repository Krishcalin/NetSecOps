# Read-only device accounts

**Audience:** network and security engineers provisioning accounts for NetSecOps.

NetSecOps only ever reads from your devices (SRS §8). The accounts you give it should
be scoped to match, so the platform's guarantee is backed by your device's own
authorization, not by our software alone. That is defence in depth: if a NetSecOps bug
ever tried to issue a write, the device itself should refuse it.

Assumption A-1 in the SRS states this explicitly: customers provision **read-only**
accounts.

---

## Why not just use an admin account?

Two reasons.

1. **It removes your last line of defence.** NetSecOps enforces an allow-list before any
   command is transmitted, and CI proves it. But a read-only device account means a
   defect on our side still cannot change your network.
2. **It shrinks the blast radius of a credential compromise.** These credentials sit in
   the NetSecOps vault, encrypted. If that vault were ever breached, the difference
   between a read-only account and a privilege-15 account is the difference between an
   information disclosure and a network takeover.

---

## Per-platform guidance

> Command and API references below are the ones NetSecOps actually uses. The complete
> allow-list per adapter is printed by `netsecops-cli audit-commands` (Phase 1) for your
> own review before you approve an onboarding.

### Cisco IOS / IOS-XE (routers, switches, Catalyst 9800 WLC)

Preferred: **privilege 1 plus command authorisation** for the `show` commands NetSecOps
needs. Privilege 15 is acceptable **only** with command allow-listing enforced via
TACACS+ command authorisation.

```
! AAA command authorisation via TACACS+ (preferred)
username netsecops privilege 1 secret <strong-password>
!
! If using local privilege escalation instead, raise only what is needed:
privilege exec level 5 show running-config
privilege exec level 5 show
username netsecops privilege 5 secret <strong-password>
```

`show running-config` requires enable mode on many images. **Entering enable mode is
permitted; entering configuration mode is not** (SRS §8.1 item 4). If your policy
forbids enable for this account, NetSecOps still collects everything reachable at
privilege 1 and marks the affected checks *Not evaluated — missing data* (FR-COL-08)
rather than failing the collection.

### Cisco NX-OS

```
role name netsecops-ro
  rule 1 permit read
username netsecops password <strong-password> role netsecops-ro
```

### Cisco ASA / Firepower FTD

ASA: privilege 5 with `show` commands permitted, or privilege 15 with command
authorisation. `show running-config` needs privilege 15 on most versions.

FTD is collected through the **FMC REST API**, not the device CLI. Create an FMC user
with a read-only role:

- FMC → System → Users → Create User → Role: **Security Analyst (Read Only)**
- NetSecOps issues `POST /api/fmc_platform/v1/auth/generatetoken` for authentication
  and `GET` for everything else.

### Cisco WLC (AireOS)

```
mgmtuser add netsecops <password> read-only
```

### Cisco ISE

ERS and OpenAPI access with a read-only admin:

- Administration → System → Admin Access → Administrators → Admin Users
- Assign the built-in **Read Only Admin** group.
- Enable ERS read access: Administration → Settings → API Settings → ERS (Read).

### Palo Alto Networks PAN-OS / Panorama

Use the built-in **`superreader`** dynamic role — read-only across the whole device.

```
set mgt-config users netsecops permissions role-based superreader yes
set mgt-config users netsecops password
```

NetSecOps generates an API key with `type=keygen` and then issues only read operations
(`type=op` with `show`, `type=config&action=show|get`, `type=export`).

### Fortinet FortiGate / FortiManager

Create an admin profile with read-only scope, then an admin using it:

```
config system accprofile
    edit "netsecops_ro"
        set secfabgrp read
        set ftviewgrp read
        set authgrp read
        set sysgrp read
        set netgrp read
        set loggrp read
        set fwgrp read
        set vpngrp read
        set utmgrp read
        set wifi read
    next
end

config system admin
    edit "netsecops"
        set accprofile "netsecops_ro"
        set trusthost1 <netsecops-worker-ip>/32
        set password <strong-password>
    next
end
```

Prefer the **REST API** over SSH for FortiGate: it is cleaner to allow-list and avoids
CLI paging entirely. If you must use SSH, pre-set `set output standard` on the account —
NetSecOps will not change console settings, because that is configuration mode.

FortiManager: a JSON-RPC user restricted to `get`. NetSecOps uses `exec` only for
`/sys/login/user` and `/sys/logout`.

**FortiSwitch and FortiAP need no account.** As of 2026-09-13
([ADR-003](adr/ADR-003-fortiswitch-fortiap-collection.md)) their data is read through the
managing FortiGate — NetSecOps never opens a session to a managed switch or access
point, and stores no credential for one. The `wifi read` and `secfabgrp read` scopes
above are what make that data visible, so do not trim them if you use fabric-managed
units.

A unit that is *not* fabric-managed therefore has no collection path. It will appear in
inventory unassessed rather than clean; if you have standalone units, either bring them
into the fabric or accept that they are out of scope and record that decision.

### Check Point Management Server / Multi-Domain

Management API with the built-in **Read Only** permission profile:

- SmartConsole → Manage & Settings → Permissions & Administrators → New Administrator
- Permission Profile: **Read Only All**
- Authentication: Check Point Password, and enable **Management API** login.

NetSecOps only ever calls `login`, `logout`, `keepalive` and `show-*` commands. It never
calls `publish`, `install-policy`, `set-*`, `add-*`, `delete-*` or `run-script`.

### Check Point Gaia (gateway OS)

Gaia clish user with the **monitor** role:

```
add user netsecops uid 0 homedir /home/netsecops
add rba user netsecops roles monitorRole
set user netsecops password
```

**Expert mode is disabled by default** in NetSecOps and stays that way unless you set
`allow_expert=true` on the device — and even then only a small allow-list of read
commands is permitted.

Expert-mode read access is **permitted for this deployment** as of 2026-09-13
([ADR-002](adr/ADR-002-checkpoint-expert-mode.md)), but permitted is not the same as
enabled. It remains per-device opt-in, because expert mode is a root shell on the
gateway: turning it on for a named device keeps the consequences of any future adapter
defect bounded to devices somebody has thought about.

If you enable it, note that the expert password is a **second credential**, separate
from the clish account's:

```
set expert-password
```

Store it in the vault alongside the clish password rather than sharing one secret
between them, and give it the same rotation treatment. A device with `allow_expert=true`
but no expert credential will report the expert-only checks as *Not Evaluated*, which is
the correct outcome — it is not a pass.

### Linux AAA hosts (FreeRADIUS, tac_plus)

An unprivileged account that can read the configuration directories:

```bash
useradd -r -s /bin/bash -m netsecops
# Grant group read on the config directories rather than using sudo where possible:
setfacl -R -m u:netsecops:rX /etc/freeradius /etc/raddb /etc/tac_plus
```

If configuration files are root-only and you cannot relax that, set
`allow_sudo_read=true` on the device and grant exactly:

```
netsecops ALL=(root) NOPASSWD: /bin/cat /etc/freeradius/*, /bin/cat /etc/tac_plus/*
```

NetSecOps then uses `sudo -n cat <path>` and nothing else.

---

## Network and transport requirements

| From | To | Port | Purpose |
|------|----|:----:|---------|
| Worker | Device | TCP/22 | SSH collection |
| Worker | Device | TCP/443 | Vendor REST/XML APIs |
| Worker | Device | UDP/161 | SNMP GET — discovery fingerprinting only, optional |
| Worker | Device | ICMP | Reachability during discovery, optional |

- **SSH v2 only.** SSHv1 and Telnet are never used. If a device only offers weak
  ciphers, NetSecOps will not silently downgrade: enabling them requires the explicit
  `ALLOW_LEGACY_SSH_CIPHERS` setting, and doing so is itself reported as a finding.
- **Host key verification** is on by default (FR-COL-10). The first collection pins the
  key; a later change raises a finding rather than being accepted silently.
- **Jump hosts** are supported per device or group (FR-COL-09) when devices are not
  directly reachable from the worker segment.

---

## Verifying the guarantee yourself

You do not have to take our word for it.

1. **Read the allow-list.** `netsecops-cli audit-commands` prints the effective
   allow-list for every adapter (Phase 1).
2. **Read the audit log.** Every command sent to every device is recorded, visible in
   the UI and exportable (FR-AUD-01).
3. **Compare config hashes.** Take a configuration hash on the device before and after
   an assessment. They will match — this is exactly what acceptance test TEST-08 does,
   on real hardware, before v1.0 ships.
