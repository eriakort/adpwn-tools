"""autobloody: needs reachable Neo4j (usually host BloodHound)."""
from __future__ import annotations

import shlex
from tools._async_runner import run_sync, launch, fetch


def autobloody_run(
    host: str,
    dbsource: str,
    dbtarget: str,
    dbpassword: str,
    password: str = "",
    domain: str = "",
    username: str = "",
    dburi: str = "bolt://host.docker.internal:7687",
    dbuser: str = "neo4j",
    secure: bool = False,
    yes: bool = False,
    extra: str = "",
    timeout: int = 300,
) -> dict:
    """
    dbsource/dbtarget: BloodHound *name* labels, case-sensitive
      e.g. ALEX.TURNER@CHECKPOINT.HTB  and  CHECKPOINT.HTB
    dburi: Neo4j from *inside the container*.
      Linux: add --add-host=host.docker.internal:host-gateway
      or use the host LAN IP (10.10.17.204:7687).
    yes=True applies the path (destructive). Default False = plan only if supported.
    """
    cmd = [
        "autobloody",
        "--host", host,
        "--dburi", dburi,
        "-du", dbuser,
        "-dp", dbpassword,
        "-ds", dbsource,
        "-dt", dbtarget,
    ]
    if domain:
        cmd += ["-d", domain]
    if username:
        cmd += ["-u", username]
    if password:
        cmd += ["-p", password]
    if secure:
        cmd.append("-s")
    if yes:
        cmd.append("-y")
    if extra:
        cmd += shlex.split(extra)
    return run_sync(cmd, timeout=timeout)
