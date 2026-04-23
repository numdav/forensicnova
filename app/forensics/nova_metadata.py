"""ForensicNova — Nova/Glance/libvirt metadata collector.

Enriches the forensic report with OpenStack-side metadata that helps a
downstream analyst (Volatility 3, Autopsy, manual investigation) pick
the right analysis profile / ISF for the dump.

Important forensic principle:
  We NEVER read anything from inside the guest.  All the data collected
  here comes from:
    - Nova API        (server details, flavor)
    - Glance API      (image properties: os_type, os_distro, architecture)
    - libvirt         (domain XML: cpu arch, memory size)
  These are the hypervisor-side facts about the VM, not its contents.

The returned dict is attached to the report as the "target_system" block.
Fields default to None when OpenStack does not advertise them (e.g. CirrOS
images carry no os_distro property).  The analyst tool (Volatility 3) will
still auto-detect OS from the dump; this block is the "best guess hint"
that comes FROM OpenStack, useful especially for thesis-scope Windows VMs
where the Glance image typically has os_type=windows / os_distro=win10.
"""
from __future__ import annotations

import logging
import os
import xml.etree.ElementTree as ET
from typing import Optional

import libvirt

log = logging.getLogger("forensicnova.forensics.nova_metadata")


def collect(
    instance_id: str,
    domain_name: str,
    libvirt_uri: str,
    cfg,
    password: Optional[str] = None,
) -> dict:
    """Collect Nova/Glance/libvirt metadata for the report's target_system.

    :param instance_id:  Nova UUID (used to query Nova API).
    :param domain_name:  libvirt domain name (used to parse domain XML).
    :param libvirt_uri:  libvirt connection URI.
    :param cfg:          ForensicNova Config instance.
    :param password:     dfir-tester password (defaults to env var if None).

    :returns: dict with nova / glance / flavor / hypervisor / libvirt subkeys.
              Missing data is represented as None, never raises — metadata
              enrichment must never block the acquisition.
    """
    result = {
        "nova":       _empty_nova(),
        "flavor":     _empty_flavor(),
        "glance":     _empty_glance(),
        "hypervisor": _empty_hypervisor(),
        "libvirt":    _empty_libvirt(domain_name),
    }

    # Nova + Glance + flavor via OpenStack APIs.
    try:
        nova_info, flavor_info, glance_info = _fetch_openstack_metadata(
            instance_id, cfg, password,
        )
        result["nova"]   = nova_info
        result["flavor"] = flavor_info
        result["glance"] = glance_info
    except Exception as exc:  # noqa: BLE001 — never block acquisition
        log.warning(
            "could not fetch OpenStack metadata for instance %s: %s",
            instance_id, exc,
        )

    # libvirt domain XML — hypervisor-side ground truth about cpu arch + mem.
    try:
        result["libvirt"] = _fetch_libvirt_metadata(libvirt_uri, domain_name)
        result["hypervisor"]["type"] = "kvm"  # DevStack deployments use KVM
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "could not fetch libvirt metadata for domain %s: %s",
            domain_name, exc,
        )

    return result


# ---------------------------------------------------------------------------
# OpenStack API client
# ---------------------------------------------------------------------------

def _fetch_openstack_metadata(
    instance_id: str, cfg, password: Optional[str],
) -> tuple[dict, dict, dict]:
    """Call Nova + Glance as dfir-tester and extract useful fields."""
    from keystoneauth1 import loading, session as ks_session
    from novaclient import client as nova_client
    from glanceclient import client as glance_client

    pwd = password or os.environ.get("FORENSICNOVA_DFIR_PASSWORD", "")
    if not pwd:
        raise EnvironmentError(
            "FORENSICNOVA_DFIR_PASSWORD not set — cannot query Nova/Glance"
        )

    loader = loading.get_plugin_loader("password")
    auth = loader.load_from_options(
        auth_url=cfg.keystone_auth_url,
        username=cfg.forensics_dfir_user,
        password=pwd,
        project_name=cfg.forensics_project,
        user_domain_id="default",
        project_domain_id="default",
    )
    sess = ks_session.Session(auth=auth)

    # Nova: server + flavor
    nova = nova_client.Client("2.1", session=sess)
    server = nova.servers.get(instance_id)

    server_info = {
        "id":         server.id,
        "name":       server.name,
        "status":     server.status,
        "created":    getattr(server, "created", None),
        "host":       getattr(server, "OS-EXT-SRV-ATTR:host", None),
        "hypervisor_hostname": getattr(server, "OS-EXT-SRV-ATTR:hypervisor_hostname", None),
    }

    flavor_ref = server.flavor or {}
    flavor_id = flavor_ref.get("id")
    flavor_info = _empty_flavor()
    if flavor_id:
        try:
            flavor = nova.flavors.get(flavor_id)
            flavor_info = {
                "id":      flavor.id,
                "name":    flavor.name,
                "ram_mb":  flavor.ram,
                "vcpus":   flavor.vcpus,
                "disk_gb": flavor.disk,
            }
        except Exception as exc:  # noqa: BLE001
            log.debug("flavor lookup failed for %s: %s", flavor_id, exc)

    # Glance: image properties (os_type, os_distro, architecture)
    image_ref = server.image or {}
    image_id = image_ref.get("id") if isinstance(image_ref, dict) else None
    glance_info = _empty_glance()
    if image_id:
        try:
            glance = glance_client.Client("2", session=sess)
            image = glance.images.get(image_id)
            glance_info = {
                "id":             image_id,
                "name":           getattr(image, "name", None),
                "disk_format":    getattr(image, "disk_format", None),
                "container_format": getattr(image, "container_format", None),
                "os_type":        getattr(image, "os_type", None),
                "os_distro":      getattr(image, "os_distro", None),
                "os_version":     getattr(image, "os_version", None),
                "architecture":   getattr(image, "architecture", None),
                "hw_machine_type": getattr(image, "hw_machine_type", None),
            }
        except Exception as exc:  # noqa: BLE001
            log.debug("glance image lookup failed for %s: %s", image_id, exc)
            glance_info["id"] = image_id  # at least keep the ID

    return server_info, flavor_info, glance_info


# ---------------------------------------------------------------------------
# libvirt domain XML parser
# ---------------------------------------------------------------------------

def _fetch_libvirt_metadata(libvirt_uri: str, domain_name: str) -> dict:
    """Parse <domain> XML to extract architecture, memory, cpu model."""
    conn = libvirt.open(libvirt_uri)
    try:
        domain = conn.lookupByName(domain_name)
        xml_str = domain.XMLDesc(0)
    finally:
        conn.close()

    root = ET.fromstring(xml_str)

    # <os><type arch="x86_64" machine="pc-q35-...">hvm</type></os>
    os_type_el = root.find("./os/type")
    arch = os_type_el.get("arch") if os_type_el is not None else None
    machine = os_type_el.get("machine") if os_type_el is not None else None

    # <memory unit="KiB">524288</memory>
    mem_el = root.find("./memory")
    mem_kib = int(mem_el.text) if mem_el is not None and mem_el.text else None

    # <vcpu>1</vcpu>
    vcpu_el = root.find("./vcpu")
    vcpus = int(vcpu_el.text) if vcpu_el is not None and vcpu_el.text else None

    # <cpu mode="..."> eventual model
    cpu_el = root.find("./cpu")
    cpu_mode = cpu_el.get("mode") if cpu_el is not None else None

    return {
        "domain_name":   domain_name,
        "architecture":  arch,
        "machine_type":  machine,
        "memory_kib":    mem_kib,
        "memory_mb":     (mem_kib // 1024) if mem_kib else None,
        "vcpus":         vcpus,
        "cpu_mode":      cpu_mode,
    }


# ---------------------------------------------------------------------------
# Default / fallback shapes (keep schema stable when lookups fail)
# ---------------------------------------------------------------------------

def _empty_nova() -> dict:
    return {
        "id": None, "name": None, "status": None,
        "created": None, "host": None, "hypervisor_hostname": None,
    }


def _empty_flavor() -> dict:
    return {"id": None, "name": None, "ram_mb": None, "vcpus": None, "disk_gb": None}


def _empty_glance() -> dict:
    return {
        "id": None, "name": None,
        "disk_format": None, "container_format": None,
        "os_type": None, "os_distro": None, "os_version": None,
        "architecture": None, "hw_machine_type": None,
    }


def _empty_hypervisor() -> dict:
    return {"type": None}


def _empty_libvirt(domain_name: str) -> dict:
    return {
        "domain_name":   domain_name,
        "architecture":  None,
        "machine_type":  None,
        "memory_kib":    None,
        "memory_mb":     None,
        "vcpus":         None,
        "cpu_mode":      None,
    }
