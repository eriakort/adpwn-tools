"""bloodyAD wrappers. Auth: password, or LM:NT via password=hashes."""
from __future__ import annotations

import shlex
from tools._async_runner import run_sync

def _base(host: str, domain: str, username: str, password: str,
          secure: bool = False, extra: str = "") -> list[str]:
    cmd = [
        "bloodyAD",
        "--host", host,
        "-d", domain,
        "-u", username,
        "-p", password,
    ]
    if secure:
        cmd.append("-s")
    if extra:
        cmd += shlex.split(extra)
    return cmd


def bloodyad_run(host: str, domain: str, username: str, password: str,
                 subcommand: str, secure: bool = False,
                 extra: str = "", timeout: int = 180) -> dict:
    """
    subcommand: everything after global flags.
    Examples:
      get writable --detail
      get object alex.turner
      get search --filter '(objectClass=msDS-DelegatedManagedServiceAccount)'
      get children 'DC=checkpoint,DC=htb'
    """
    cmd = _base(host, domain, username, password, secure, extra) + shlex.split(subcommand)
    return run_sync(cmd, timeout=timeout)


def bloodyad_writable(host: str, domain: str, username: str, password: str,
                      detail: bool = True, otype: str = "ALL",
                      right: str = "ALL", secure: bool = False) -> dict:
    args = f"get writable --otype {otype} --right {right}"
    if detail:
        args += " --detail"
    return bloodyad_run(host, domain, username, password, args, secure=secure)


def bloodyad_object(host: str, domain: str, username: str, password: str,
                    target: str, attr: str = "", secure: bool = False) -> dict:
    sub = f"get object {shlex.quote(target)}"
    if attr:
        sub += f" --attr {attr}"
    return bloodyad_run(host, domain, username, password, sub, secure=secure)


def bloodyad_search(host: str, domain: str, username: str, password: str,
                    ldap_filter: str, attr: str = "", secure: bool = False) -> dict:
    sub = f"get search --filter {shlex.quote(ldap_filter)}"
    if attr:
        sub += f" --attr {attr}"
    return bloodyad_run(host, domain, username, password, sub, secure=secure)
