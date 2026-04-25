"""kerb-chain — playbook-driven AD attack chain orchestrator.

Consumes kerb-map's JSON output (or any compatible findings list),
walks an attack playbook, executes each play via shelled-out impacket
/ certipy / netexec, captures loot, feeds it back into subsequent
plays. The differentiator nobody else is shipping in 2026.

Public API:

    from kerb_chain import Engagement, Playbook, Runner, load_findings

    findings   = load_findings("kerb-map_corp.local_*.json")
    engagement = Engagement.from_findings(findings, dry_run=True)
    playbook   = Playbook.from_file("playbooks/standard.yaml")
    Runner(playbook, engagement).run()
"""

from kerb_chain.engagement import Engagement, Loot
from kerb_chain.findings import load_findings
from kerb_chain.playbook import Play, Playbook
from kerb_chain.runner import Runner

__all__ = [
    "Engagement",
    "Loot",
    "Play",
    "Playbook",
    "Runner",
    "load_findings",
]
