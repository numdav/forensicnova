# ForensicNova

> **Status**: 🚧 Active development — FASE 4 completed (memory acquisition pipeline), FASE 5 in planning (PDF report + web dashboard)
>
> OpenStack DevStack plugin for **forensically-sound volatile memory acquisition** of running VM instances, designed around DFIR (Digital Forensics & Incident Response) best practices.

## Overview

**ForensicNova** extends OpenStack with a REST API (`/api/v1/servers/<id>/memory_acquire`) that performs **hypervisor-level RAM acquisition** from running guest instances without altering the target VM's filesystem, timestamps, or unallocated space. Dumps are hashed (MD5 + SHA-1), archived on Swift together with a machine-readable chain-of-custody record, and — in FASE 5 — paired with a printable PDF report designed for analyst countersignature.

The plugin is distributed as a standard **DevStack plugin** and integrates with OpenStack via Keystone authentication, a dedicated `forensic_analyst` role, and Swift object storage.

## Why hypervisor-level?

Running acquisition tools *inside* the guest OS is forensically weak:

- any tool execution modifies the target's memory, syscall table, registry, logs
- a compromised guest can tamper with or deceive the agent
- acquisition method must be identical regardless of guest OS

ForensicNova acquires RAM from the **compute host** via `libvirt coreDumpWithFormat()` (equivalent to `virsh dump --memory-only --format raw`), so the guest is never touched and the output is natively compatible with **Volatility 3**.

## Architecture

```
┌──────────────────────────────────────────────────┐
│  OpenStack control plane                         │
│  ┌─────────┐   ┌─────────┐   ┌──────────────┐    │
│  │Keystone │   │  Nova   │   │    Swift     │    │
│  └────┬────┘   └────┬────┘   └──────▲───────┘    │
│       │ auth        │ metadata      │ upload     │
│       ▼             ▼               │            │
│  ┌──────────────────────────────────────────┐    │
│  │       ForensicNova plugin (:5234)        │    │
│  │  REST API ─ libvirt ─ hash ─ etag-verify │    │
│  └──────────────────┬───────────────────────┘    │
│                     │ libvirt coreDump           │
│                     ▼                            │
│  ┌──────────────────────────────────────────┐    │
│  │  Compute node │ libvirt │ QEMU/KVM       │    │
│  │           [ target VM ]                  │    │
│  └──────────────────────────────────────────┘    │
└──────────────────────────────────────────────────┘
```

## Forensic soundness — the six guarantees

1. **Zero bit written in the guest filesystem**. RAM is read via libvirt/QEMU at hypervisor level; the guest OS is unaware.
2. **Hypervisor-local staging in a dedicated forensic dir** (`/var/lib/forensicnova/acquisitions/<uuid>/`, mode 600, owned by the service user).
3. **Streaming MD5+SHA-1** computed on the hypervisor BEFORE any network transfer (chunks of 64 KB, O(1) RAM).
4. **Swift end-to-end integrity verification** — the Swift etag returned on PUT is the server-computed MD5 of the object; we compare it to our locally-computed MD5.  Mismatch → abort, log, preserve local dump for forensic debug.
5. **Secure-delete of the hypervisor-local dump** after successful upload (`shred -u -n 1`).  Rationale: RAM may contain credentials/keys — no persistence of secrets on the hypervisor.
6. **Chain-of-custody JSONL audit log** on the hypervisor (`/var/log/forensicnova/chain-of-custody.jsonl`), one event per line (acquisition start, domain lookup, dump start/stop, hash start/stop, upload start/verified, secure-delete, errors).

## Feature matrix

| Capability                               | Prototype (exam)  | M.Sc. thesis |
|------------------------------------------|:-----------------:|:------------:|
| REST API `memory_acquire`                | ✅                | ✅           |
| Hypervisor-level RAW dump (guest-agnostic) | ✅              | ✅           |
| MD5 + SHA-1 chain of custody             | ✅                | ✅           |
| Swift-backed artifact storage            | ✅                | ✅           |
| Swift etag end-to-end verification       | ✅                | ✅           |
| Secure-delete of local dump              | ✅                | ✅           |
| Keystone `forensic_analyst` role         | ✅                | ✅           |
| Cross-tenant metadata enrichment (Nova/Glance) | ✅          | ✅           |
| JSON report (schema v1.1)                | ✅                | ✅           |
| Signable PDF report (ReportLab)          | ⏳ FASE 5        | ✅           |
| Standalone Flask dashboard (:5234)       | ⏳ FASE 5        | ✅           |
| Dashboard: acquisition list + download   | ⏳ FASE 5        | ✅           |
| Dashboard: trigger acquisition from UI   | ⏳ FASE 5        | ✅           |
| Volatility 3 IOC extraction              | ⏳                | ✅           |
| YARA rule matching                       | ⏳                | ✅           |
| Threat Intelligence (MISP / STIX)        | ⏳                | ✅           |
| Unified forensic timeline                | ⏳                | ✅           |

## Quick start (DevStack)

Add to your `local.conf`:

```ini
[[local|localrc]]
enable_plugin forensicnova https://github.com/numdav/forensicnova main

# required by the plugin to create the DFIR test user
FORENSICNOVA_DFIR_PASSWORD=<choose-a-strong-password>
```

Then run `./stack.sh` as usual. The plugin:

1. creates the Keystone artifacts (`forensic_analyst` role, `forensics` project, `dfir-tester` user)
2. grants `dfir-tester` the `admin` role on every project (required by Nova's cross-tenant policy)
3. creates the Swift container `forensics`
4. writes `/etc/forensicnova/forensicnova.conf` and a helper openrc file at `/opt/stack/devstack/openrc-dfir`
5. creates a dedicated Python venv at `/opt/stack/forensicnova/.venv`
6. installs and starts a systemd unit `devstack@forensicnova.service` listening on port 5234

Verify with:

```bash
curl http://<host-ip>:5234/health
```

Expected:

```json
{"service":"forensicnova","status":"ok","version":"0.1.0"}
```

## Using the API

```bash
# become the DFIR analyst
source /opt/stack/devstack/openrc-dfir
TOKEN=$(openstack token issue -c id -f value)

# pick any running Nova instance
INSTANCE_ID=$(openstack server list -c ID -f value | head -1)

# acquire RAM
curl -X POST \
    -H "X-Auth-Token: $TOKEN" \
    http://<host-ip>:5234/api/v1/servers/$INSTANCE_ID/memory_acquire
```

The response is a JSON summary with the acquisition UUID, both Swift object names (dump + report), and hash values.  The full forensic report lives inside Swift as the second object.

## Swift object naming

```
dump-<sanitized_vm_name>-<YYYYMMDDTHHMMSSZ>.raw
report-<sanitized_vm_name>-<YYYYMMDDTHHMMSSZ>.json
```

The VM name is the Nova `server.name`, sanitized so only `[a-zA-Z0-9-]` remain (other chars → `_`).  The acquisition UUID remains the canonical unique key inside the report and the Swift custom metadata.

## Report schema v1.1 highlights

- `timestamps`: `started_at`, `completed_at`, `duration_seconds`
- `instance`: Nova UUID + name + libvirt domain
- `target_system`: metadata from Nova + Glance + libvirt domain XML that help Volatility 3 auto-select the right ISF/profile (OS type, architecture, memory size, cpu model).  Collected **without ever reading from inside the guest**.
- `dump`: size, MD5, SHA-1, Swift object, etag, etag_verified
- `report`: self-referencing block with the report's own Swift object name
- `chain_of_custody`: ordered, numbered, human-described list of all events

## Repository layout

```
forensicnova/
├── devstack/
│   ├── plugin.sh              # 4 DevStack phases + unstack + clean
│   └── settings               # configurable variables
├── app/
│   ├── __init__.py            # Flask app factory
│   ├── config.py              # INI loader
│   ├── wsgi.py                # systemd entry point
│   ├── api/
│   │   ├── __init__.py        # /health blueprint
│   │   └── v1.py              # /api/v1/* authenticated endpoints
│   ├── forensics/
│   │   ├── acquirer.py        # libvirt dump + chown + secure_delete
│   │   └── nova_metadata.py   # Nova/Glance/libvirt XML collector
│   ├── hashing/
│   │   └── hasher.py          # streaming MD5+SHA-1
│   ├── storage/
│   │   └── swift_client.py    # PUT with etag verification
│   ├── reports/
│   │   ├── chain_of_custody.py# append-only JSONL writer
│   │   └── json_report.py     # schema v1.1 builder
│   └── dashboard/             # empty — FASE 5
├── README.md
└── local.conf.example
```

## Tech stack

Python 3 · Flask · libvirt-python · keystonemiddleware · python-swiftclient · python-novaclient · python-glanceclient · hashlib · ReportLab (FASE 5)

## Target environment

Ubuntu 24.04 LTS · DevStack `master` (2026.2) · KVM with nested virtualization · Swift single-node

## Known limitations

### DevStack-only: Swift data lost after `unstack → stack`

Swift uses the Keystone project UUID as the storage namespace (`AUTH_<project_id>`).  In DevStack, `unstack.sh` + `stack.sh` destroys and recreates Keystone projects with fresh UUIDs, so any previously stored Swift objects become orphaned in namespaces that no longer exist.  The underlying filesystem inside `swift.img` is preserved, but the data is unreachable via the Swift API.

This is a DevStack-specific behavior (DevStack is an ephemeral test environment by design).  **In a production OpenStack deployment, project UUIDs are stable for the lifetime of the cloud, so Swift objects persist indefinitely**.

For development and demo purposes, regular reboots of the host VM do NOT cause data loss — only the explicit `unstack → stack` sequence does.

### Cross-tenant forensic analyst privileges

To query Nova/Glance metadata for VMs owned by any tenant, `dfir-tester` is granted the `admin` role on every existing project by the plugin.  This is the DFIR analyst contract: cross-tenant visibility is required for incident response.  In production, this would be backed by a dedicated Nova `policy.yaml` override restricting `forensic_analyst` to read-only cross-tenant operations (thesis scope).

### fstab discipline after unstack

After every `./unstack.sh` (or interrupted `./stack.sh`), the operator must ensure `/etc/fstab` does not accumulate duplicate `swift.img` lines before any reboot or subsequent `./stack.sh`.  Rule: `grep -c swift.img /etc/fstab` must return `0` (before stack) or `1` (after successful stack).  This is a DevStack known issue unrelated to the plugin.

## Academic context

Developed as exam project for *Piattaforme di Cloud Computing* and as baseline for M.Sc. thesis — Università degli Studi di Salerno, ISISLab.

## License

To be defined.  Likely Apache-2.0 (consistent with OpenStack ecosystem).

---

**Author**: Davide Numelli (numdav)
