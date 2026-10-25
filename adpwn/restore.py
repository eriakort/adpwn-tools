"""
adpwn.restore – RestoreOperation: replay a .restore journal in reverse.

Usage (non-interactive, from adpwn_tools.py):
    op = RestoreOperation(restore_file, server=host)
    op._passwords[(username.lower(), domain.lower())] = password_or_hash
    op.run(interactive=False)
"""
from __future__ import annotations

import json
import getpass
from typing import Any

import ldap3

from .config import Identity, connect_ldap, AuthError
from . import primitives
from .primitives import PrimitiveError, _SD_DACL, _SD_OWNER, _write_sd


class RestoreException(Exception):
    """Raised when a restore step fails."""


class RestoreOperation:
    """
    Reads a restore journal produced by ExploitState.save_restore_data()
    and replays each entry in reverse order to undo the AD changes.

    Parameters
    ----------
    restore_file:
        Path to the ``.restore`` JSON file.
    server:
        Override the DC to connect to (useful when the original server is
        no longer reachable).
    """

    def __init__(self, restore_file: str, server: str | None = None):
        with open(restore_file, "r") as fh:
            self._doc = json.load(fh)

        self._file   = restore_file
        self._server = server or self._doc["identity"]["server"]
        self._domain = self._doc["identity"].get("domain", "")
        self._user   = self._doc["identity"].get("user", "")
        self._history: list[dict] = self._doc.get("history", [])

        # Pre-populate with restored credentials from caller.
        # Key: (username_lower, domain_lower)  →  value: password or LMHASH:NTHASH
        self._passwords: dict[tuple[str, str], str] = {}

    # ------------------------------------------------------------------
    def _get_password(self, username: str, domain: str,
                      interactive: bool) -> str:
        key = (username.lower(), domain.lower())
        if key in self._passwords:
            return self._passwords[key]
        if interactive:
            pw = getpass.getpass(f"Password for {domain}\\{username}: ")
            self._passwords[key] = pw
            return pw
        raise RestoreException(
            f"No password available for {domain}\\{username}. "
            "Pre-populate RestoreOperation._passwords or use interactive=True."
        )

    def _build_conn(self, interactive: bool) -> ldap3.Connection:
        username = self._user
        domain   = self._domain
        password = self._get_password(username, domain, interactive)
        identity = Identity(
            user=username,
            password=password,
            domain=domain,
            server=self._server,
        )
        try:
            return connect_ldap(identity)
        except AuthError as exc:
            raise RestoreException(f"LDAP auth failed during restore: {exc}") from exc

    # ------------------------------------------------------------------
    def run(self, interactive: bool = False) -> None:
        """
        Execute restore steps in reverse order.

        Raises RestoreException on the first step that cannot be reversed
        (unless the entry was marked ``reversible=False``, which is skipped
        with a warning).
        """
        conn = self._build_conn(interactive)

        for entry in reversed(self._history):
            op          = entry["operation"]
            data        = entry["data"]
            reversible  = entry.get("reversible", True)
            target_dn   = data.get("target_dn", "")

            if not reversible:
                print(f"[restore] SKIP {op} on {target_dn} (not reversible)")
                continue

            print(f"[restore] Reversing {op} on {target_dn} …")

            try:
                if op in ("grant_full_control", "grant_dcsync",
                          "grant_addmember_privilege"):
                    self._restore_sd(conn, target_dn, data["original_sd"],
                                     flags=_SD_DACL)

                elif op == "write_owner":
                    self._restore_sd(conn, target_dn, data["original_sd"],
                                     flags=_SD_OWNER)

                elif op == "add_group_member":
                    group_dn  = data.get("group_dn",  target_dn)
                    member_dn = data.get("member_dn", "")
                    if member_dn:
                        primitives.remove_group_member(conn, group_dn, member_dn)
                    else:
                        raise RestoreException(
                            f"Cannot restore add_group_member: member_dn missing in {data}"
                        )

                elif op == "add_rbcd":
                    orig = data.get("original_rbcd", "")
                    attr = "msDS-AllowedToActOnBehalfOfOtherIdentity"
                    if orig:
                        conn.modify(
                            target_dn,
                            {attr: [(ldap3.MODIFY_REPLACE, [bytes.fromhex(orig)])]}
                        )
                    else:
                        # Attribute was absent before – delete it
                        conn.modify(target_dn, {attr: [(ldap3.MODIFY_DELETE, [])]})
                    rc = conn.result.get("result", -1)
                    if rc != 0:
                        raise RestoreException(
                            f"RBCD restore failed for {target_dn}: rc={rc}"
                        )

                elif op == "reset_password":
                    print(f"[restore] WARNING: cannot restore original password "
                          f"for {target_dn} – manual action required")
                    continue

                else:
                    print(f"[restore] Unknown operation {op!r} – skipping")
                    continue

                print(f"[restore] OK  {op} on {target_dn}")

            except (PrimitiveError, RestoreException) as exc:
                raise RestoreException(
                    f"Restore step {op}/{target_dn} failed: {exc}"
                ) from exc

    # ------------------------------------------------------------------
    @staticmethod
    def _restore_sd(conn: ldap3.Connection, dn: str, original_sd_hex: str,
                    flags: int) -> None:
        sd_bytes = bytes.fromhex(original_sd_hex)
        _write_sd(conn, dn, sd_bytes, flags=flags)
