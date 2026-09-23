# adpwn-tools

AD privilege-escalation toolkit combining bloodyAD LDAP primitives with aclpwn-style ACL path exploitation. Built as async MCP tool wrappers for pentestmcp.

## Files

- adpwn_tools.py - Core async wrappers around the adpwn Python API. LDAP manipulation and restore journaling.
- bloodyad_tool.py - Subprocess wrappers around the bloodyAD CLI for enumeration.
- autobloody_tool.py - Wrapper around autobloody for graph-driven ACL path exploitation via BloodHound/Neo4j.

## Primitives (adpwn_tools.py)

Each function makes a targeted LDAP write to escalate AD privileges:

- adpwn_add_generic_all: Grant GenericAll over any object
- adpwn_add_dcsync: Grant DCSync rights on the domain root
- adpwn_add_group_member: Add a principal to an AD group
- adpwn_remove_group_member: Remove a principal from an AD group
- adpwn_set_owner: Change object ownership (WriteOwner abuse)
- adpwn_set_password: Force-reset a user password
- adpwn_add_rbcd: Configure RBCD on a computer object
- adpwn_add_addmember_priv: Grant AddMember right to a trustee
- adpwn_restore_journal: Undo all recorded LDAP changes from a restore journal

## Restore Journaling

Every write primitive creates a restore journal (.restore file). Use adpwn_restore_journal to replay it in reverse and clean up post-engagement.

## Authentication

Accepts plaintext password or pass-the-hash (NT hash or LM:NT format).

## Requirements

- Python 3.10+
- adpwn package vendored at ../adpwn/
- bloodyAD and autobloody in PATH
- FastMCP / asyncio (pentestmcp)

---

For authorized penetration testing and red team engagements only.
