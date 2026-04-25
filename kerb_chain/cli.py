"""kerb-chain CLI.

Usage:

    kerb-chain run --findings scan.json --playbook playbooks/standard.yaml
    kerb-chain run --findings scan.json --playbook standard --dry-run
    kerb-chain show --findings scan.json
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from kerb_chain.engagement import Credential, Engagement
from kerb_chain.findings import index_by_attack, load_findings
from kerb_chain.playbook import Playbook
from kerb_chain.runner import Runner

PROMPT_SENTINEL = "<<KERBCHAIN_PROMPT>>"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="kerb-chain",
        description="Playbook-driven AD attack chain orchestrator",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    # ── run ──
    run = sub.add_parser("run", help="Execute a playbook against findings")
    run.add_argument("--findings", required=True, type=Path,
                     help="kerb-map JSON output (full_data shape or bare findings list)")
    run.add_argument("--playbook", required=True,
                     help="playbook name or path to .yaml file")
    run.add_argument("--operator-user", default=None,
                     help="seed credential username (defaults to scan operator)")
    run.add_argument("--operator-pass", nargs="?", const=PROMPT_SENTINEL, default=None,
                     help="seed password (omit value to prompt)")
    run.add_argument("--operator-pass-env", default=None,
                     help="read seed password from named env var")
    run.add_argument("--operator-hash", default=None,
                     help="seed NT hash (alternative to password)")
    run.add_argument("--domain", default=None, help="override scan domain")
    run.add_argument("--dc-ip",  default=None, help="override DC IP")
    run.add_argument("--run-dir", default=None, type=Path,
                     help="loot/journal output directory")
    run.add_argument("--dry-run", action="store_true",
                     help="render commands and evaluate conditions without executing")
    run.add_argument("--aggressive", action="store_true",
                     help="enable plays that touch the network or create AD objects")
    run.add_argument("--quiet", action="store_true",
                     help="suppress per-play progress output")
    run.add_argument("--only-category", default=None,
                     help="restrict to plays whose category matches")

    # ── show ──
    show = sub.add_parser("show", help="Print the findings + which plays would match")
    show.add_argument("--findings", required=True, type=Path)
    show.add_argument("--playbook", required=False, default=None,
                      help="if given, also show which plays would run")

    return p


def cmd_run(args) -> int:
    findings = load_findings(args.findings)
    if not findings:
        print(f"[!] {args.findings}: no findings to chain on; exiting.")
        return 0

    operator = _resolve_operator(args)
    pb_path = _resolve_playbook(args.playbook)
    playbook = Playbook.from_file(pb_path)

    engagement = Engagement.from_findings(
        findings,
        domain=args.domain or "",
        dc_ip=args.dc_ip or "",
        operator_cred=operator,
        run_dir=args.run_dir,
        dry_run=args.dry_run,
    )

    if args.only_category:
        playbook.plays = [p for p in playbook.plays if p.category == args.only_category]

    print(f"[*] kerb-chain: domain={engagement.domain or '?'}  "
          f"dc={engagement.dc_ip or '?'}  findings={len(findings)}  "
          f"playbook={playbook.name}  "
          f"{'dry-run' if args.dry_run else 'live'}"
          f"{' aggressive' if args.aggressive else ''}")
    if engagement.run_dir:
        print(f"    run_dir: {engagement.run_dir}")

    runner = Runner(playbook, engagement,
                    aggressive=args.aggressive, verbose=not args.quiet)
    runner.run()

    journal = engagement.write_journal()
    print(f"\n[*] {len(engagement.history)} play records written to {journal}")
    print(f"    loot: {len(engagement.loot.credentials)} creds, "
          f"{len(engagement.loot.tickets)} tickets, "
          f"{len(engagement.loot.certificates)} certs, "
          f"{len(engagement.loot.owned_hosts)} owned hosts")
    return 0


def cmd_show(args) -> int:
    findings = load_findings(args.findings)
    grouped = index_by_attack(findings)
    print(f"[*] {len(findings)} findings across {len(grouped)} attack types")
    for attack, group in sorted(grouped.items(), key=lambda kv: -len(kv[1])):
        print(f"  {len(group):4}  {attack}")

    if args.playbook:
        pb = Playbook.from_file(_resolve_playbook(args.playbook))
        # Use a dry-run engagement so condition evaluation can read loot/state.
        eng = Engagement.from_findings(findings, dry_run=True)
        from kerb_chain.playbook import evaluate_condition
        print(f"\n[*] playbook '{pb.name}' — plays that would activate now:")
        for play in pb.plays:
            if play.per == "finding":
                hits = sum(
                    1 for f in findings
                    if evaluate_condition(play.when, finding=f, engagement=eng)
                )
                if hits:
                    print(f"  ✓ {play.name:30}  ×{hits}  ({play.category})")
            else:
                if evaluate_condition(play.when, finding=None, engagement=eng):
                    print(f"  ✓ {play.name:30}  ×1   ({play.category})")
    return 0


# ────────────────────────────────────────────────────────────────────── #
#  Helpers                                                               #
# ────────────────────────────────────────────────────────────────────── #


def _resolve_operator(args) -> Credential | None:
    user = args.operator_user
    if not user:
        return None
    if args.operator_hash:
        return Credential(username=user, domain="", nt_hash=args.operator_hash,
                          source="cli")
    if args.operator_pass_env:
        pw = os.environ.get(args.operator_pass_env)
        if pw is None:
            print(f"[!] env var {args.operator_pass_env} not set", file=sys.stderr)
            sys.exit(1)
        return Credential(username=user, domain="", password=pw, source="cli")
    if args.operator_pass == PROMPT_SENTINEL:
        return Credential(username=user, domain="",
                          password=getpass.getpass("Password: "), source="cli")
    if args.operator_pass:
        return Credential(username=user, domain="", password=args.operator_pass,
                          source="cli")
    return None


def _resolve_playbook(name_or_path: str) -> Path:
    """Allow ``--playbook standard`` to find ``playbooks/standard.yaml``
    bundled with the install, falling back to the literal path."""
    p = Path(name_or_path)
    if p.exists():
        return p
    bundled = Path(__file__).parent / "playbooks" / f"{name_or_path}.yaml"
    if bundled.exists():
        return bundled
    raise FileNotFoundError(f"playbook '{name_or_path}' not found "
                            f"(tried {p} and {bundled})")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.cmd == "run":
        return cmd_run(args)
    if args.cmd == "show":
        return cmd_show(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
