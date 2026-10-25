"""adpwn.config – Identity dataclass and LDAP connection helper."""
from __future__ import annotations

import ldap3
from ldap3.core.exceptions import LDAPBindError, LDAPSocketOpenError


class AuthError(Exception):
    """Raised when LDAP authentication fails."""


class Identity:
    """Holds connection parameters for one AD account."""

    def __init__(self, user: str, password: str, domain: str, server: str):
        self.user = user
        self.password = password
        self.domain = domain
        self.server = server

    def __repr__(self):
        return f"<Identity {self.domain}\\{self.user} @ {self.server}>"


def connect_ldap(identity: Identity) -> ldap3.Connection:
    """
    Create and return a bound ldap3 Connection to the DC.

    Authentication is NTLM.  The password field may be either:
      - A plain password string
      - An LMHASH:NTHASH string (pass-the-hash)

    Pass-the-hash via pure ldap3 has limitations; for full PtH support use
    bloodyAD or autobloody (subprocess wrappers in this same repo).
    """
    srv = ldap3.Server(
        identity.server,
        port=389,
        use_ssl=False,
        get_info=ldap3.ALL,
        connect_timeout=10,
    )

    user_str = f"{identity.domain}\\{identity.user}"

    try:
        conn = ldap3.Connection(
            srv,
            user=user_str,
            password=identity.password,
            authentication=ldap3.NTLM,
            auto_bind=True,
            raise_exceptions=False,
        )
    except (LDAPBindError, LDAPSocketOpenError) as exc:
        raise AuthError(f"LDAP bind failed ({identity.server}): {exc}") from exc
    except Exception as exc:
        raise AuthError(f"LDAP connection error: {exc}") from exc

    if conn.result and conn.result.get("result", 0) != 0:
        raise AuthError(
            f"LDAP bind rejected ({identity.server}): "
            f"{conn.result.get('description', 'unknown')} "
            f"(rc={conn.result['result']})"
        )

    return conn
