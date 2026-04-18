# ForensicNova

> **Status**: 🚧 Active development — prototype phase
>
> OpenStack plugin for forensically-sound volatile memory acquisition of running VM instances, designed around DFIR (Digital Forensics & Incident Response) best practices.

## Overview

**ForensicNova** extends OpenStack Nova with a REST action (`memory_acquire`) that performs **hypervisor-level RAM acquisition** from running guest instances without altering the target VM's filesystem, timestamps, or unallocated space. Dumps are hashed (MD5 + SHA-1), archived on Swift together with a machine-readable chain-of-custody record, and paired with a printable PDF report designed for analyst countersignature.

The plugin is distributed as a standard **DevStack plugin** and integrates with OpenStack via Keystone authentication, a dedicated `forensic_analyst` role, and Swift object storage.

## Why hypervisor-level?

Running acquisition tools *inside* the guest OS is forensically weak:

- any tool execution modifies the target's memory, syscall table, registry, logs
- a compromised guest can tamper with or deceive the agent
- acquisition method must be identical regardless of guest OS

ForensicNova acquires RAM from the **compute host** via `virsh dump --memory-only --format raw` against libvirt, so the guest is never touched and the output is natively compatible with **Volatility 3**.

## Architecture (prototype)

```
┌──────────────────────────────────────────────────┐
│  OpenStack control plane                         │
│  ┌─────────┐   ┌─────────┐   ┌──────────────┐    │
│  │Keystone │   │  Nova   │   │    Swift     │    │
│  └────┬────┘   └────┬────┘   └──────▲───────┘    │
│       │ auth       │ action          │ upload    │
│       ▼            ▼                 │           │
│  ┌──────────────────────────────────────────┐    │
│  │       ForensicNova plugin (:5234)        │    │
│  │   REST API ─ virsh dump ─ hashing ─ ...  │    │
│  └──────────────────┬───────────────────────┘    │
│                     │ virsh dump                 │
│                     ▼                            │
│  ┌──────────────────────────────────────────┐    │
│  │  Compute node │ libvirt │ QEMU/KVM       │    │
│  │           [ target VM ]                  │    │
│  └──────────────────────────────────────────┘    │
└──────────────────────────────────────────────────┘
```

## Feature matrix

| Capability | Prototype (exam) | M.Sc. thesis |
|---|:---:|:---:|
| `memory_acquire` Nova REST action | ✅ | ✅ |
| Hypervisor-level RAW dump (guest-agnostic) | ✅ | ✅ |
| MD5 + SHA-1 chain of custody | ✅ | ✅ |
| Swift-backed artifact storage | ✅ | ✅ |
| Keystone `forensic_analyst` role | ✅ | ✅ |
| JSON + signable PDF reports | ✅ | ✅ |
| Standalone Flask dashboard (:5234) | ✅ | ✅ |
| Volatility 3 IOC extraction | ⏳ | ✅ |
| YARA rule matching | ⏳ | ✅ |
| Threat Intelligence (MISP / STIX) | ⏳ | ✅ |
| Unified forensic timeline | ⏳ | ✅ |

## Quick start (DevStack)

Add to your `local.conf`:

```ini
[[local|localrc]]
enable_plugin forensicnova https://github.com/numdav/forensicnova main
```

Then run `./stack.sh` as usual. Full setup and usage instructions coming soon.

## Repository layout

```
forensicnova/
├── devstack/          # DevStack plugin integration
│   ├── plugin.sh      # pre-install / install / post-config / extra
│   └── settings       # configurable variables
├── app/               # Python application code
│   ├── api/           # REST endpoints + Nova action
│   ├── forensics/     # virsh dump wrapper
│   ├── hashing/       # MD5 + SHA-1 computation
│   ├── storage/       # Swift client + chain of custody
│   ├── reports/       # JSON + PDF report generation
│   └── dashboard/     # Flask web UI (:5234)
├── local.conf.example # Sample DevStack configuration
└── README.md
```

## Tech stack

Python 3 · Flask · libvirt / `virsh` · `hashlib` · OpenStack Swift · OpenStack Keystone (`keystonemiddleware`) · ReportLab

## Target environment

Ubuntu 24.04 LTS · DevStack `master` (2026.2) · KVM with nested virtualization · Swift single-node

## Academic context

Developed as exam project for *Piattaforme di Cloud Computing* and as baseline for M.Sc. thesis — Università degli Studi di Salerno, ISISLab.

## License

To be defined. Likely Apache-2.0 (consistent with OpenStack ecosystem).

---

**Author**: Davide Numelli
